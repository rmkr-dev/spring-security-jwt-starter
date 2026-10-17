package io.github.rmkrdev.entra.security.core.jwt;

import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Accepts a token only when its {@code iss} claim exactly matches one of the allowed issuers
 * (typically the tenant's v1 {@code https://sts.windows.net/{tid}/} and v2
 * {@code https://login.microsoftonline.com/{tid}/v2.0} issuers).
 */
public final class EntraIssuerValidator implements OAuth2TokenValidator<Jwt> {

    private final Set<String> issuers;

    public EntraIssuerValidator(Collection<String> issuers) {
        if (issuers == null || issuers.isEmpty()) {
            throw new IllegalArgumentException("At least one allowed issuer is required");
        }
        this.issuers = Set.copyOf(new TreeSet<>(issuers));
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        String issuer = token.getClaimAsString("iss");
        if (issuer != null && issuers.contains(issuer)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                "The iss claim is not an allowed issuer for this tenant", null));
    }

    public Set<String> getIssuers() {
        return issuers;
    }
}
