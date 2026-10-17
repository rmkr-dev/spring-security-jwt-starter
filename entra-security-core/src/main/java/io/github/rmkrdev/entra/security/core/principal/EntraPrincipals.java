package io.github.rmkrdev.entra.security.core.principal;

import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Static access to the current {@link EntraPrincipal}, for code that cannot take it as a parameter.
 */
public final class EntraPrincipals {

    private EntraPrincipals() {
    }

    /**
     * The principal of the current request, if it was authenticated with an Entra token.
     */
    public static Optional<EntraPrincipal> current() {
        return from(SecurityContextHolder.getContext().getAuthentication());
    }

    /**
     * The principal of the current request.
     *
     * @throws IllegalStateException when the request is not authenticated with an Entra token
     */
    public static EntraPrincipal require() {
        return current().orElseThrow(() -> new IllegalStateException(
                "No authenticated EntraPrincipal in the current security context"));
    }

    public static Optional<EntraPrincipal> from(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof EntraPrincipal principal) {
            return Optional.of(principal);
        }
        return Optional.empty();
    }
}
