package io.github.rmkrdev.entra.security.core.outbound;

import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

import io.github.rmkrdev.entra.security.core.token.EntraTokenAcquisitionException;

/**
 * Finds the access token the current request was authenticated with, which the on-behalf-of flow sends to
 * Entra as the user assertion.
 */
public final class EntraUserTokens {

    private EntraUserTokens() {
    }

    /** The token of the current thread's security context, if it was authenticated with a JWT. */
    public static Optional<Jwt> current() {
        return from(SecurityContextHolder.getContext().getAuthentication());
    }

    /** The JWT behind an authentication ({@code EntraAuthenticationToken}, {@code JwtAuthenticationToken}). */
    public static Optional<Jwt> from(Authentication authentication) {
        if (authentication instanceof AbstractOAuth2TokenAuthenticationToken<?> token
                && token.getToken() instanceof Jwt jwt) {
            return Optional.of(jwt);
        }
        if (authentication != null && authentication.getCredentials() instanceof Jwt jwt) {
            return Optional.of(jwt);
        }
        return Optional.empty();
    }

    static EntraTokenAcquisitionException missing() {
        return new EntraTokenAcquisitionException("An on-behalf-of call needs the current user's access token, but "
                + "the security context holds none. Call on-behalf-of clients while handling a request "
                + "authenticated with an Entra bearer token (on WebFlux, inside the request's reactive chain)",
                "invalid_request", null);
    }
}
