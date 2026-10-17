package io.github.rmkrdev.entra.security.core.token;

import java.time.Instant;

/**
 * An access token acquired from Entra ID.
 *
 * @param value     the bearer token
 * @param expiresAt when the token expires
 */
public record AccessToken(String value, Instant expiresAt) {

    @Override
    public String toString() {
        return "AccessToken[value=****, expiresAt=" + expiresAt + "]";
    }
}
