package io.github.rmkrdev.entra.security.core.token;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Acquires app-only tokens with the OAuth 2.0 client credentials grant against the Entra v2 token
 * endpoint, and caches them per scope until shortly before they expire.
 */
public final class ClientCredentialsTokenProvider implements EntraTokenProvider {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final URI tokenEndpoint;
    private final String clientId;
    private final EntraCredential credential;
    private final RestClient restClient;
    private final Duration refreshSkew;
    private final Clock clock;
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
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.credential = credential;
        this.restClient = restClient;
        this.refreshSkew = refreshSkew;
        this.clock = clock;
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
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("scope", scope);
        credential.contribute(form, tokenEndpoint, clientId);
        Instant requestedAt = clock.instant();
        JsonNode body;
        try {
            body = restClient.post()
                    .uri(tokenEndpoint)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(form)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (request, response) -> {
                        throw error(response.getStatusCode().value(), response.getBody());
                    })
                    .body(JsonNode.class);
        }
        catch (EntraTokenAcquisitionException ex) {
            throw ex;
        }
        catch (RestClientException ex) {
            throw new EntraTokenAcquisitionException("Token request to " + tokenEndpoint + " failed: "
                    + ex.getMessage(), null, ex);
        }
        if (body == null || !body.hasNonNull("access_token")) {
            throw new EntraTokenAcquisitionException("Token response from " + tokenEndpoint
                    + " did not contain an access_token", null, null);
        }
        long expiresIn = body.path("expires_in").asLong(300);
        Instant expiresAt = requestedAt.plusSeconds(expiresIn);
        Duration lifetime = Duration.ofSeconds(expiresIn);
        Duration skew = refreshSkew.compareTo(lifetime.dividedBy(2)) > 0 ? lifetime.dividedBy(2) : refreshSkew;
        return new CachedToken(new AccessToken(body.get("access_token").asText(), expiresAt), expiresAt.minus(skew));
    }

    private EntraTokenAcquisitionException error(int status, InputStream bodyStream) {
        String error = null;
        String description = null;
        try (InputStream in = bodyStream) {
            JsonNode node = JSON.readTree(in);
            if (node != null) {
                error = node.path("error").asText(null);
                description = node.path("error_description").asText(null);
            }
        }
        catch (IOException | RuntimeException ignored) {
            // non-JSON error body
        }
        StringBuilder message = new StringBuilder("Token request to ").append(tokenEndpoint)
                .append(" for client ").append(clientId).append(" failed with HTTP ").append(status);
        if (error != null) {
            message.append(": ").append(error);
        }
        if (description != null) {
            message.append(" - ").append(description.lines().findFirst().orElse(description));
        }
        return new EntraTokenAcquisitionException(message.toString(), error, null);
    }

    private record CachedToken(AccessToken token, Instant refreshAt) {

        boolean isFresh(Instant now) {
            return now.isBefore(refreshAt);
        }
    }
}
