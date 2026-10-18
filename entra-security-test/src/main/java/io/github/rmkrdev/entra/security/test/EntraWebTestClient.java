package io.github.rmkrdev.entra.security.test;

import java.util.function.Consumer;

import org.springframework.http.HttpHeaders;

/**
 * {@code WebTestClient} helpers for WebFlux services.
 *
 * <pre>{@code
 * client.get().uri("/api/orders").headers(bearer(tokens.user().groups(READERS))).exchange()
 *       .expectStatus().isOk();
 * }</pre>
 */
public final class EntraWebTestClient {

    private EntraWebTestClient() {
    }

    /** Sets {@code Authorization: Bearer <token>} with the token built from the given builder. */
    public static Consumer<HttpHeaders> bearer(EntraTestTokens.TokenBuilder token) {
        return bearer(token.build());
    }

    /** Sets {@code Authorization: Bearer <token>}. */
    public static Consumer<HttpHeaders> bearer(String token) {
        String value = token.startsWith("Bearer ") ? token : "Bearer " + token;
        return headers -> headers.set(HttpHeaders.AUTHORIZATION, value);
    }
}
