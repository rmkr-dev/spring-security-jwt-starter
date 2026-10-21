package io.github.rmkrdev.entra.security.core.jwt;

import java.util.Collection;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Accepts a token only when it carries an Entra access-token claim: {@code idtyp}, a non-empty {@code scp},
 * or a non-empty {@code roles}. An ID token, whose {@code aud} is often the client id, has none of those.
 */
public final class EntraAccessTokenValidator implements OAuth2TokenValidator<Jwt> {

    static final String DESCRIPTION = "The token is not an Entra access token";

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (isAccessToken(token)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, DESCRIPTION, null));
    }

    /**
     * {@code true} when the token has {@code idtyp}, delegated scopes, or app roles.
     */
    public static boolean isAccessToken(Jwt token) {
        String idtyp = token.getClaimAsString(EntraClaimNames.IDENTITY_TYPE);
        if (idtyp != null && !idtyp.isBlank()) {
            return true;
        }
        if (!EntraClaims.scopes(token).isEmpty()) {
            return true;
        }
        Object roles = token.getClaims().get(EntraClaimNames.ROLES);
        if (roles instanceof String text) {
            return !text.isBlank();
        }
        return roles instanceof Collection<?> values && !values.isEmpty();
    }
}
