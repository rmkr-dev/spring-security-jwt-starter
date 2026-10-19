package io.github.rmkrdev.entra.security.core.token;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Exchanges a user's incoming access token for a token to a downstream API, on behalf of that user
 * (the OAuth 2.0 on-behalf-of flow, {@code urn:ietf:params:oauth:grant-type:jwt-bearer}).
 */
@FunctionalInterface
public interface EntraOnBehalfOfTokenProvider {

    /**
     * @param userToken the validated delegated token this API received
     * @param scope     the downstream scopes, space separated, such as {@code api://orders/Orders.Read} or
     *                  {@code api://orders/.default}
     * @return a delegated token for the downstream API, valid for at least a short while
     * @throws EntraInteractionRequiredException when the user must consent or satisfy a policy first
     * @throws EntraTokenAcquisitionException    when Entra refuses for another reason or cannot be reached
     */
    AccessToken getToken(Jwt userToken, String scope);

    /**
     * A fresh token that satisfies a claims challenge from the downstream API (Continuous Access Evaluation).
     * The default ignores the claims.
     *
     * @param claims the decoded challenge claims, as JSON
     */
    default AccessToken getToken(Jwt userToken, String scope, String claims) {
        return getToken(userToken, scope);
    }
}
