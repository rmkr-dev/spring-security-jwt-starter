package io.github.rmkrdev.entra.security.test;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Builds the security context for {@link WithMockEntraUser}.
 */
public class WithMockEntraUserSecurityContextFactory extends AbstractMockEntraSecurityContextFactory<WithMockEntraUser> {

    @Override
    Jwt toJwt(WithMockEntraUser annotation) {
        return userJwt(annotation);
    }

    @Override
    List<String> extraRoles(WithMockEntraUser annotation) {
        return Arrays.asList(annotation.roles());
    }
}
