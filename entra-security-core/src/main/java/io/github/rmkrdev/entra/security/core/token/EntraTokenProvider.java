package io.github.rmkrdev.entra.security.core.token;

/**
 * Supplies app-only access tokens for a resource scope, such as {@code api://peer-api/.default}.
 */
@FunctionalInterface
public interface EntraTokenProvider {

    /**
     * @param scope the resource scope, ending in {@code /.default} for client credentials
     * @return a token that is valid for at least a short while
     * @throws EntraTokenAcquisitionException when Entra refuses or cannot be reached
     */
    AccessToken getToken(String scope);

    /**
     * A fresh token that satisfies a claims challenge from the resource (Continuous Access Evaluation). The
     * default ignores the claims.
     *
     * @param claims the decoded challenge claims, as JSON
     */
    default AccessToken getToken(String scope, String claims) {
        return getToken(scope);
    }
}
