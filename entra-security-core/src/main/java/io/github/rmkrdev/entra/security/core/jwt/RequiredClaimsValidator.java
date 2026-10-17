package io.github.rmkrdev.entra.security.core.jwt;

import java.util.List;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Rejects tokens that are missing claims every Entra access token carries.
 */
public final class RequiredClaimsValidator implements OAuth2TokenValidator<Jwt> {

    private final List<String> claims;

    public RequiredClaimsValidator(List<String> claims) {
        this.claims = List.copyOf(claims);
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        for (String claim : claims) {
            if (!token.hasClaim(claim)) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                        "The " + claim + " claim is required", null));
            }
        }
        return OAuth2TokenValidatorResult.success();
    }
}
