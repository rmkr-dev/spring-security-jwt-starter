package io.github.rmkrdev.entra.security.core.introspect;

import java.net.URI;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Checks a token by presenting it to a userinfo-style endpoint, such as Microsoft Graph {@code /oidc/userinfo} or
 * {@code /v1.0/me}. Meant for tokens whose audience is Microsoft Graph, which this API cannot validate itself.
 * <p>
 * {@code 200} is an active token whose claims are the response body; {@code 401} and {@code 403} are inactive;
 * anything else is an {@link IntrospectionException}. This proves that the endpoint accepts the token for that
 * user. It does not prove the token was issued for this API.
 */
public final class UserInfoTokenIntrospector implements TokenIntrospector {

    private static final ParameterizedTypeReference<Map<String, Object>> MAP = new ParameterizedTypeReference<>() {
    };

    private final RestClient restClient;
    private final URI endpoint;

    public UserInfoTokenIntrospector(RestClient restClient, URI endpoint) {
        this.restClient = restClient;
        this.endpoint = endpoint;
    }

    @Override
    public IntrospectionResult introspect(String token) {
        Map<String, Object> body;
        try {
            body = restClient.get()
                    .uri(endpoint)
                    .accept(MediaType.APPLICATION_JSON)
                    .headers(headers -> headers.setBearerAuth(token))
                    .retrieve()
                    .body(MAP);
        }
        catch (HttpClientErrorException ex) {
            if (ex.getStatusCode().isSameCodeAs(HttpStatus.UNAUTHORIZED)
                    || ex.getStatusCode().isSameCodeAs(HttpStatus.FORBIDDEN)) {
                return IntrospectionResult.inactive();
            }
            throw new IntrospectionException("Userinfo check at " + endpoint + " failed: " + ex.getMessage(), ex);
        }
        catch (RestClientException ex) {
            throw new IntrospectionException("Userinfo check at " + endpoint + " failed: " + ex.getMessage(), ex);
        }
        if (body == null) {
            throw new IntrospectionException("Userinfo check at " + endpoint + " returned no body", null);
        }
        return IntrospectionResult.active(body);
    }

    public URI getEndpoint() {
        return endpoint;
    }
}
