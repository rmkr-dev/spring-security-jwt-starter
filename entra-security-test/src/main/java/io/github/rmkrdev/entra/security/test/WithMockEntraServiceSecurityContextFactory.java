package io.github.rmkrdev.entra.security.test;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Builds the security context for {@link WithMockEntraService}.
 */
public class WithMockEntraServiceSecurityContextFactory
        extends AbstractMockEntraSecurityContextFactory<WithMockEntraService> {

    @Override
    Jwt toJwt(WithMockEntraService annotation) {
        return serviceJwt(annotation);
    }

    @Override
    List<String> extraRoles(WithMockEntraService annotation) {
        return Arrays.asList(annotation.roles());
    }
}
