package io.github.rmkrdev.entra.security.core.jwt;

import java.io.Closeable;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RateLimitedJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RetryingJWKSetSource;
import com.nimbusds.jose.jwk.source.URLBasedJWKSetSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;

/**
 * The JWKS source with background refresh, so requests are served from memory and never wait for a JWKS
 * fetch once the keys are loaded.
 * <p>
 * Keys are cached for {@code cacheTtl}. In the last {@code refreshAhead} of that lifetime a lookup returns
 * the cached keys and refreshes them on a background thread. A daemon timer makes such a lookup every
 * {@code refreshAhead / 2}, so the keys are refreshed even without traffic. An unknown {@code kid} still
 * triggers a rate-limited refresh (at most one every 30 seconds), and a failed fetch is retried once.
 * {@link #warm()} loads the keys up front, typically at startup.
 */
public final class EntraJwkSource implements JWKSource<SecurityContext>, Closeable {

    private static final Logger log = LoggerFactory.getLogger(EntraJwkSource.class);
    private static final long RATE_LIMIT_MILLIS = 30_000;
    private static final JWKSelector ALL = new JWKSelector(new JWKMatcher.Builder().build());
    private static final AtomicInteger THREADS = new AtomicInteger();

    private final URI jwksUri;
    private final JWKSetBasedJWKSource<SecurityContext> delegate;
    private final ExecutorService refresher;
    private final ScheduledExecutorService timer;

    /**
     * @param jwksUri        the JWKS endpoint
     * @param retriever      fetches the document, with its own connect and read timeouts
     * @param cacheTtl       how long fetched keys are used
     * @param refreshTimeout how long a request waits for a fetch another thread started
     * @param refreshAhead   background refresh window before {@code cacheTtl} ends; zero or {@code null}
     *                       disables background refresh (keys are then refreshed on the request that finds
     *                       them expired). Capped at half of {@code cacheTtl} and at {@code cacheTtl} minus
     *                       {@code refreshTimeout}
     */
    public EntraJwkSource(URI jwksUri, ResourceRetriever retriever, Duration cacheTtl, Duration refreshTimeout,
            Duration refreshAhead) {
        this.jwksUri = jwksUri;
        JWKSetSource<SecurityContext> source;
        try {
            source = new URLBasedJWKSetSource<>(jwksUri.toURL(), retriever);
        }
        catch (MalformedURLException | IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid JWKS URI: " + jwksUri, ex);
        }
        source = new RetryingJWKSetSource<>(source, null);
        long ttl = cacheTtl.toMillis();
        source = new RateLimitedJWKSetSource<>(source, Math.min(RATE_LIMIT_MILLIS, Math.max(1, ttl - 1)), null);
        long ahead = refreshAhead == null ? 0
                : Math.min(refreshAhead.toMillis(), Math.min(ttl / 2, ttl - refreshTimeout.toMillis()));
        if (ahead > 0) {
            refresher = Executors.newSingleThreadExecutor(daemon("entra-jwks-refresh"));
            source = new RefreshAheadCachingJWKSetSource<>(source, ttl, refreshTimeout.toMillis(), ahead, false,
                    refresher, true, null);
            timer = Executors.newSingleThreadScheduledExecutor(daemon("entra-jwks-timer"));
            long period = Math.max(1000, ahead / 2);
            timer.scheduleWithFixedDelay(this::tick, period, period, TimeUnit.MILLISECONDS);
        }
        else {
            refresher = null;
            timer = null;
            source = new com.nimbusds.jose.jwk.source.CachingJWKSetSource<>(source, ttl, refreshTimeout.toMillis(),
                    null);
        }
        this.delegate = new JWKSetBasedJWKSource<>(source);
    }

    @Override
    public List<JWK> get(JWKSelector selector, SecurityContext context) throws KeySourceException {
        return delegate.get(selector, context);
    }

    /**
     * Loads the keys now, unless they are already cached.
     *
     * @return the number of keys
     * @throws KeySourceException when the JWKS cannot be fetched
     */
    public int warm() throws KeySourceException {
        return delegate.get(ALL, null).size();
    }

    /** Whether background refresh is active. */
    public boolean isRefreshingAhead() {
        return timer != null;
    }

    public URI getJwksUri() {
        return jwksUri;
    }

    private void tick() {
        try {
            delegate.get(ALL, null);
        }
        catch (Exception ex) {
            log.debug("Background JWKS refresh from {} failed: {}", jwksUri, ex.getMessage());
        }
    }

    @Override
    public void close() throws IOException {
        if (timer != null) {
            timer.shutdownNow();
        }
        delegate.close();
    }

    private static ThreadFactory daemon(String name) {
        return runnable -> {
            Thread thread = new Thread(runnable, name + "-" + THREADS.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }
}
