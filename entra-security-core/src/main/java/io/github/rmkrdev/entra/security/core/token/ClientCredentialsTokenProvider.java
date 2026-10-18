package io.github.rmkrdev.entra.security.core.token;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;

/**
 * Acquires app-only tokens with the OAuth 2.0 client credentials grant against the Entra v2 token
 * endpoint, and caches them per scope until shortly before they expire.
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

    @Override
    public AccessToken getToken(String scope) {
        CachedToken cached = cache.get(scope);
        if (cached != null && cached.isFresh(clock.instant())) {
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

    public String getClientId() {
        return clientId;
    }

    public URI getTokenEndpoint() {
        return tokenEndpoint;
    }

    private CachedToken fetch(String scope) {
        long start = System.nanoTime();
        try {
            CachedToken fresh = requestToken(scope);
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

    private CachedToken requestToken(String scope) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("scope", scope);
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
