package io.github.rmkrdev.entra.security.core.token;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import io.github.rmkrdev.entra.security.core.cae.ContinuousAccessEvaluation;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;

/**
 * Acquires app-only tokens with the OAuth 2.0 client credentials grant against the Entra v2 token
 * endpoint, and caches them per scope until shortly before they expire.
 * <p>
 * With a background executor ({@link #withBackgroundRefresh(Executor)}), a token inside its refresh window is
 * still returned at once and renewed on the executor, so callers only wait for the token endpoint when no
 * valid token is cached at all.
 */
public final class ClientCredentialsTokenProvider implements EntraTokenProvider {

    private final URI tokenEndpoint;
    private final String clientId;
    private final EntraCredential credential;
    private final TokenEndpointClient endpoint;
    private final Duration refreshSkew;
    private final Clock clock;
    private final EntraSecurityObservations observations;
    private final Map<String, CachedToken> cache = new ConcurrentHashMap<>();
    private final Map<String, Object> locks = new ConcurrentHashMap<>();
    private final Map<String, Boolean> refreshing = new ConcurrentHashMap<>();
    private static final Logger log = LoggerFactory.getLogger(ClientCredentialsTokenProvider.class);
    private static final Duration MIN_REMAINING = Duration.ofSeconds(30);
    private volatile Executor refresher;
    private volatile boolean clientCapabilities;

    /**
     * @param tokenEndpoint the token endpoint, see {@link #tokenEndpoint(URI, String)}
     * @param clientId      the client (application) id
     * @param credential    how the client authenticates
     * @param restClient    HTTP client
     * @param refreshSkew   how long before expiry a cached token is renewed
     * @param clock         time source
     */
    public ClientCredentialsTokenProvider(URI tokenEndpoint, String clientId, EntraCredential credential,
            RestClient restClient, Duration refreshSkew, Clock clock) {
        this(tokenEndpoint, clientId, credential, restClient, refreshSkew, clock, EntraSecurityObservations.NO_OP);
    }

    /**
     * @param observations notified on token-endpoint calls only; cache hits are silent.
     *                     {@code null} is treated as {@link EntraSecurityObservations#NO_OP}
     */
    public ClientCredentialsTokenProvider(URI tokenEndpoint, String clientId, EntraCredential credential,
            RestClient restClient, Duration refreshSkew, Clock clock, EntraSecurityObservations observations) {
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.credential = credential;
        this.endpoint = new TokenEndpointClient(tokenEndpoint, clientId, restClient, clock);
        this.refreshSkew = refreshSkew;
        this.clock = clock;
        this.observations = observations == null ? EntraSecurityObservations.NO_OP : observations;
    }

    /**
     * The v2 token endpoint for a tenant: {@code {authorityHost}/{tenantId}/oauth2/v2.0/token}.
     */
    public static URI tokenEndpoint(URI authorityHost, String tenantId) {
        String host = authorityHost.toString();
        if (host.endsWith("/")) {
            host = host.substring(0, host.length() - 1);
        }
        return URI.create(host + "/" + tenantId + "/oauth2/v2.0/token");
    }

    /**
     * Renews tokens in their refresh window on {@code executor} instead of on the calling thread.
     *
     * @return this provider
     */
    public ClientCredentialsTokenProvider withBackgroundRefresh(Executor executor) {
        this.refresher = executor;
        return this;
    }

    /**
     * Declares the {@code cp1} client capability on every token request, so Entra issues CAE-capable tokens.
     *
     * @return this provider
     */
    public ClientCredentialsTokenProvider withClientCapabilities() {
        this.clientCapabilities = true;
        return this;
    }

    @Override
    public AccessToken getToken(String scope, String claims) {
        if (claims == null || claims.isBlank()) {
            return getToken(scope);
        }
        synchronized (locks.computeIfAbsent(scope, key -> new Object())) {
            CachedToken fresh = fetch(scope, claims);
            cache.put(scope, fresh);
            return fresh.token();
        }
    }

    @Override
    public AccessToken getToken(String scope) {
        CachedToken cached = cache.get(scope);
        Instant now = clock.instant();
        if (cached != null && cached.isFresh(now)) {
            return cached.token();
        }
        Executor executor = refresher;
        if (executor != null && cached != null && now.plus(MIN_REMAINING).isBefore(cached.token().expiresAt())) {
            refreshInBackground(scope, executor);
            return cached.token();
        }
        synchronized (locks.computeIfAbsent(scope, key -> new Object())) {
            cached = cache.get(scope);
            if (cached != null && cached.isFresh(clock.instant())) {
                return cached.token();
            }
            CachedToken fresh = fetch(scope);
            cache.put(scope, fresh);
            return fresh.token();
        }
    }

    private void refreshInBackground(String scope, Executor executor) {
        if (refreshing.putIfAbsent(scope, Boolean.TRUE) != null) {
            return;
        }
        try {
            executor.execute(() -> {
                try {
                    cache.put(scope, fetch(scope));
                }
                catch (RuntimeException ex) {
                    log.warn("Early renewal of the token for scope {} failed; using the cached token: {}", scope,
                            ex.getMessage());
                }
                finally {
                    refreshing.remove(scope);
                }
            });
        }
        catch (RuntimeException ex) {
            refreshing.remove(scope);
        }
    }

    public String getClientId() {
        return clientId;
    }

    public URI getTokenEndpoint() {
        return tokenEndpoint;
    }

    private CachedToken fetch(String scope) {
        return fetch(scope, null);
    }

    private CachedToken fetch(String scope, String challenge) {
        long start = System.nanoTime();
        try {
            CachedToken fresh = requestToken(scope, challenge);
            observations.tokenAcquisition(EntraSecurityObservations.GRANT_CLIENT_CREDENTIALS,
                    credential.credentialType(), true, elapsed(start));
            return fresh;
        }
        catch (RuntimeException ex) {
            observations.tokenAcquisition(EntraSecurityObservations.GRANT_CLIENT_CREDENTIALS,
                    credential.credentialType(), false, elapsed(start));
            throw ex;
        }
    }

    private CachedToken requestToken(String scope, String challenge) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("scope", scope);
        String claims = ContinuousAccessEvaluation.requestClaims(clientCapabilities, challenge);
        if (claims != null) {
            form.add("claims", claims);
        }
        credential.contribute(form, tokenEndpoint, clientId);
        TokenEndpointClient.IssuedToken issued = endpoint.request(form, endpoint::defaultError);
        return new CachedToken(issued.token(), TokenEndpointClient.refreshAt(issued, refreshSkew));
    }

    private static Duration elapsed(long startNanos) {
        return Duration.ofNanos(System.nanoTime() - startNanos);
    }

    private record CachedToken(AccessToken token, Instant refreshAt) {

        boolean isFresh(Instant now) {
            return now.isBefore(refreshAt);
        }
    }
}
