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
}
