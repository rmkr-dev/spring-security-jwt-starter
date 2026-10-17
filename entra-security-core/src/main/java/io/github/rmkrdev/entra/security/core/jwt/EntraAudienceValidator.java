package io.github.rmkrdev.entra.security.core.jwt;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Accepts a token only when one of its {@code aud} values is an allowed audience
 * (by default {@code api://<clientId>} and {@code <clientId>}).
 */
public final class EntraAudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final Set<String> audiences;

    public EntraAudienceValidator(Collection<String> audiences) {
        if (audiences == null || audiences.isEmpty()) {
            throw new IllegalArgumentException("At least one allowed audience is required");
        }
        this.audiences = Set.copyOf(audiences);
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        List<String> tokenAudiences = token.getAudience();
        if (tokenAudiences != null && tokenAudiences.stream().anyMatch(audiences::contains)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                "The aud claim does not match this API", null));
    }

    public Set<String> getAudiences() {
        return audiences;
    }
}
