package io.github.rmkrdev.entra.security.core.introspect;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.Supplier;

import org.springframework.http.HttpHeaders;
import org.springframework.util.MultiValueMap;

/**
 * How this API authenticates to an RFC 7662 introspection endpoint.
 */
public abstract class IntrospectionClientAuthentication {

    private IntrospectionClientAuthentication() {
    }

    /** Adds the credentials to the request headers or form. */
    abstract void apply(HttpHeaders headers, MultiValueMap<String, String> form);

    /** HTTP Basic with the form-urlencoded client id and secret (RFC 6749 section 2.3.1). */
    public static IntrospectionClientAuthentication clientSecretBasic(String clientId, String clientSecret) {
        String user = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
        String password = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        String value = "Basic " + Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
        return new IntrospectionClientAuthentication() {
            @Override
            void apply(HttpHeaders headers, MultiValueMap<String, String> form) {
                headers.set(HttpHeaders.AUTHORIZATION, value);
            }
        };
    }

    /** {@code client_id} and {@code client_secret} in the request body. */
    public static IntrospectionClientAuthentication clientSecretPost(String clientId, String clientSecret) {
        return new IntrospectionClientAuthentication() {
            @Override
            void apply(HttpHeaders headers, MultiValueMap<String, String> form) {
                form.add("client_id", clientId);
                form.add("client_secret", clientSecret);
            }
        };
    }

    /** A bearer token, for example an app-only token from this API's own credential. */
    public static IntrospectionClientAuthentication bearer(Supplier<String> token) {
        return new IntrospectionClientAuthentication() {
            @Override
            void apply(HttpHeaders headers, MultiValueMap<String, String> form) {
                headers.setBearerAuth(token.get());
            }
        };
    }

    /** No client authentication, for endpoints protected otherwise (for example a sidecar on localhost). */
    public static IntrospectionClientAuthentication none() {
        return new IntrospectionClientAuthentication() {
            @Override
            void apply(HttpHeaders headers, MultiValueMap<String, String> form) {
            }
        };
    }
}
