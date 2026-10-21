package io.github.rmkrdev.entra.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;

import com.nimbusds.jose.jwk.RSAKey;

import io.github.rmkrdev.entra.security.autoconfigure.health.EntraJwksReactiveHealthIndicator;

class EntraSecurityRuntimeHintsTest {

    @Test
    void registersConfigurationResourcesAndNimbusReflection() {
        RuntimeHints hints = new RuntimeHints();
        new EntraSecurityRuntimeHints().registerHints(hints, getClass().getClassLoader());

        assertThat(RuntimeHintsPredicates.resource().forResource(
                "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports")).accepts(hints);
        assertThat(RuntimeHintsPredicates.reflection().onType(EntraSecurityAutoConfiguration.class)).accepts(hints);
        assertThat(RuntimeHintsPredicates.reflection().onType(RSAKey.class)).accepts(hints);
        assertThat(RuntimeHintsPredicates.reflection().onType(EntraSpringBootVersionCheck.class)).accepts(hints);
        assertThat(RuntimeHintsPredicates.reflection().onType(EntraJwksReactiveHealthIndicator.class)).accepts(hints);
    }
}
