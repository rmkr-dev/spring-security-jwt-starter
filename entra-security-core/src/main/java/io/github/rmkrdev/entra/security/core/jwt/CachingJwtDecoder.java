package io.github.rmkrdev.entra.security.core.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import io.github.rmkrdev.entra.security.core.cache.TokenKeys;
import io.github.rmkrdev.entra.security.core.cache.TtlCache;

/**
 * Remembers successfully validated tokens, so a token presented again skips parsing, the signature check
 * and the claim validators.
 * <p>
 * Entries are keyed by a SHA-256 hash of the token and kept for {@code ttl}, but never past the token's
 * {@code exp} plus the clock skew, so a cached token is never accepted after the validators would have
 * rejected it. Failures are not cached. A signing key that Entra removes keeps validating cached tokens for
 * at most {@code ttl}.
 */
public final class CachingJwtDecoder implements JwtDecoder {

    private final JwtDecoder delegate;
    private final TtlCache<String, Jwt> cache;
    private final Duration clockSkew;
    private final Clock clock;

    public CachingJwtDecoder(JwtDecoder delegate, Duration ttl, int maxEntries, Duration clockSkew, Clock clock) {
        this(delegate, ttl, maxEntries, clockSkew, clock, false);
    }

    /**
     * @param bounded when {@code true}, the cache stays within {@code maxEntries} under concurrency and one
     *                validation runs per token
     */
    public CachingJwtDecoder(JwtDecoder delegate, Duration ttl, int maxEntries, Duration clockSkew, Clock clock,
            boolean bounded) {
        this.delegate = delegate;
        this.cache = new TtlCache<>(ttl, maxEntries, clock, bounded);
        this.clockSkew = clockSkew == null ? Duration.ZERO : clockSkew;
        this.clock = clock;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        if (token == null) {
            return delegate.decode(null);
        }
        String key = TokenKeys.of(token);
        if (cache.isBounded()) {
            Jwt cached = cache.getIfPresent(key);
            if (cached != null) {
                return cached;
            }
            return cache.coalesce(key, () -> remember(key, token));
        }
        return remember(key, token);
    }

    private Jwt remember(String key, String token) {
        Jwt cached = cache.getIfPresent(key);
        if (cached != null) {
            return cached;
        }
        Jwt jwt = delegate.decode(token);
        Instant expiresAt = jwt.getExpiresAt();
        if (expiresAt != null) {
            cache.put(key, jwt, Duration.between(clock.instant(), expiresAt.plus(clockSkew)));
        }
        return jwt;
    }

    /** Number of cached tokens. */
    public int size() {
        return cache.size();
    }

    public JwtDecoder getDelegate() {
        return delegate;
    }
}
