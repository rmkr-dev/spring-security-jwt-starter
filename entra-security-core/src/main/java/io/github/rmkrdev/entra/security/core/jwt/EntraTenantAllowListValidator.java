package io.github.rmkrdev.entra.security.core.jwt;

import java.util.Collection;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Accepts a token only when its {@code tid} claim is one of the configured directory ids.
 */
public final class EntraTenantAllowListValidator implements OAuth2TokenValidator<Jwt> {

    private final Set<String> tenantIds;

    public EntraTenantAllowListValidator(Collection<String> tenantIds) {
        if (tenantIds == null || tenantIds.isEmpty()) {
            throw new IllegalArgumentException("At least one allowed tenant id is required");
        }
        this.tenantIds = tenantIds.stream()
                .map(id -> id.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        String tid = token.getClaimAsString(EntraClaimNames.TENANT_ID);
        if (tid != null && tenantIds.contains(tid.toLowerCase(Locale.ROOT))) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                "The tid claim does not match an allowed tenant", null));
    }
}
