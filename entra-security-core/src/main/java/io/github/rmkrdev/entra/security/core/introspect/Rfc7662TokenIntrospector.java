package io.github.rmkrdev.entra.security.core.introspect;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Checks tokens against an OAuth 2.0 token introspection endpoint (RFC 7662).
 * <p>
 * Microsoft Entra ID does not offer such an endpoint; use this with a gateway or custom authorization server
 * that does. A {@code 200} answer with {@code "active": true} is an active token, any other {@code 200} answer is
 * inactive, and every other status (including a rejected client credential) is an {@link IntrospectionException}.
 */
public final class Rfc7662TokenIntrospector implements TokenIntrospector {

    private static final ParameterizedTypeReference<Map<String, Object>> MAP = new ParameterizedTypeReference<>() {
    };

    private final RestClient restClient;
    private final URI endpoint;
    private final IntrospectionClientAuthentication authentication;
    private final String tokenTypeHint;

    /**
     * @param restClient     HTTP client with connect and read timeouts
     * @param endpoint       the introspection endpoint
     * @param authentication how this API authenticates to the endpoint
     * @param tokenTypeHint  {@code token_type_hint}, usually {@code access_token}; {@code null} to omit it
     */
    public Rfc7662TokenIntrospector(RestClient restClient, URI endpoint,
            IntrospectionClientAuthentication authentication, String tokenTypeHint) {
        this.restClient = restClient;
        this.endpoint = endpoint;
        this.authentication = authentication;
        this.tokenTypeHint = tokenTypeHint;
    }

    @Override
    public IntrospectionResult introspect(String token) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        if (tokenTypeHint != null && !tokenTypeHint.isBlank()) {
            form.add("token_type_hint", tokenTypeHint);
        }
        Map<String, Object> body;
        try {
            body = restClient.post()
                    .uri(endpoint)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.APPLICATION_JSON)
                    .headers(headers -> authentication.apply(headers, form))
                    .body(form)
                    .retrieve()
                    .body(MAP);
        }
        catch (RestClientException ex) {
            throw new IntrospectionException("Token introspection at " + endpoint + " failed: " + ex.getMessage(),
                    ex);
        }
        if (body == null) {
            throw new IntrospectionException("Token introspection at " + endpoint + " returned no body", null);
        }
        if (!Boolean.TRUE.equals(body.get("active"))) {
            return IntrospectionResult.inactive();
        }
        Map<String, Object> claims = new LinkedHashMap<>(body);
        claims.remove("active");
        return IntrospectionResult.active(claims);
    }

    public URI getEndpoint() {
        return endpoint;
    }
}
