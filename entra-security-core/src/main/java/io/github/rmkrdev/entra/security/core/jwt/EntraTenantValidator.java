package io.github.rmkrdev.entra.security.core.jwt;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Accepts a token only when its {@code tid} claim equals the configured tenant id.
 */
public final class EntraTenantValidator implements OAuth2TokenValidator<Jwt> {

    private final String tenantId;

    public EntraTenantValidator(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }
        this.tenantId = tenantId;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        String tid = token.getClaimAsString(EntraClaimNames.TENANT_ID);
        if (tenantId.equalsIgnoreCase(tid)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                "The tid claim does not match the configured tenant", null));
    }
}
