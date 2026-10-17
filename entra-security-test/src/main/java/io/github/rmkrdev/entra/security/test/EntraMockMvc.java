package io.github.rmkrdev.entra.security.test;

import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * MockMvc helpers.
 *
 * <pre>{@code
 * mvc.perform(get("/api/orders").with(bearer(tokens.user().groups(READERS))))
 * }</pre>
 */
public final class EntraMockMvc {

    private EntraMockMvc() {
    }

    /** Adds {@code Authorization: Bearer <token>} with the token built from the given builder. */
    public static RequestPostProcessor bearer(EntraTestTokens.TokenBuilder token) {
        return bearer(token.build());
    }

    /** Adds {@code Authorization: Bearer <token>}. */
    public static RequestPostProcessor bearer(String token) {
        String value = token.startsWith("Bearer ") ? token : "Bearer " + token;
        return request -> {
            request.addHeader(HttpHeaders.AUTHORIZATION, value);
            return request;
        };
    }
}
