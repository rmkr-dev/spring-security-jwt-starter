package io.github.rmkrdev.entra.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;

class EntraFeatureFlagPropertiesTest {

    @Test
    void flagsAreOffAndASingleTenantIsUnchanged() {
        EntraSecurityProperties properties = configured("11111111-1111-1111-1111-111111111111");

        assertThat(properties.getValidation().isRejectIdTokens()).isFalse();
        assertThat(properties.getCache().isBounded()).isFalse();
        assertThat(properties.getMultiTenant().isEnabled()).isFalse();
        assertThat(properties.resolveAcceptedTenantIds()).isEmpty();
        assertThat(properties.resolveRequiredTenantId()).isEqualTo("11111111-1111-1111-1111-111111111111");
        assertThat(properties.resolveJwkSetUri().toString())
                .isEqualTo("https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys");
        assertThat(properties.resolveIssuers()).containsExactly(
                "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
                "https://sts.windows.net/11111111-1111-1111-1111-111111111111/");
        assertThat(violations(properties)).isEmpty();
    }

    @Test
    void organizationsRequiresTheMultiTenantFlag() {
        assertThat(violations(configured("organizations"))).isNotEmpty();
        assertThat(violations(configured("consumers"))).isNotEmpty();
    }

    @Test
    void multiTenantFlagAcceptsAnAllowListAndUsesCommonKeys() {
        EntraSecurityProperties properties = configured("organizations");
        properties.getMultiTenant().setEnabled(true);
        properties.getMultiTenant().setTenantIds(List.of("22222222-2222-2222-2222-222222222222"));
        properties.getValidation().setRejectIdTokens(true);
        properties.getCache().setBounded(true);

        assertThat(violations(properties)).isEmpty();
        assertThat(properties.getValidation().isRejectIdTokens()).isTrue();
        assertThat(properties.getCache().isBounded()).isTrue();
        assertThat(properties.resolveAcceptedTenantIds()).containsExactly("22222222-2222-2222-2222-222222222222");
        assertThat(properties.resolveRequiredTenantId()).isNull();
        assertThat(properties.resolveIssuers()).containsExactly(
                "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0",
                "https://sts.windows.net/22222222-2222-2222-2222-222222222222/");
        assertThat(properties.resolveJwkSetUri().toString())
                .isEqualTo("https://login.microsoftonline.com/common/discovery/v2.0/keys");
    }

    @Test
    void multiTenantFlagIncludesTheHomeTenantGuid() {
        EntraSecurityProperties properties = configured("11111111-1111-1111-1111-111111111111");
        properties.getMultiTenant().setEnabled(true);
        properties.getMultiTenant().setTenantIds(List.of("22222222-2222-2222-2222-222222222222"));

        assertThat(violations(properties)).isEmpty();
        assertThat(properties.resolveAcceptedTenantIds()).containsExactly(
                "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222");
    }

    @Test
    void multiTenantFlagWithoutAGuidFailsStartupValidation() {
        EntraSecurityProperties properties = configured("organizations");
        properties.getMultiTenant().setEnabled(true);

        assertThat(violations(properties)).isNotEmpty();
    }

    private static EntraSecurityProperties configured(String tenantId) {
        EntraSecurityProperties properties = new EntraSecurityProperties();
        properties.setTenantId(tenantId);
        properties.setClientId("33333333-3333-3333-3333-333333333333");
        return properties;
    }

    private static Set<ConstraintViolation<EntraSecurityProperties>> violations(EntraSecurityProperties properties) {
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            return factory.getValidator().validate(properties);
        }
    }
}
