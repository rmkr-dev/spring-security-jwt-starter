package io.github.rmkrdev.entra.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.assertThatNoException;

import java.io.InputStream;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.SpringBootVersion;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.mock.env.MockEnvironment;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSpringBootVersionCheck.Result;

class EntraSpringBootVersionCheckTest {

    @ParameterizedTest
    @CsvSource({
            "4.1.1, SUPPORTED",
            "4.1.0-RC1, SUPPORTED",
            "4.1.12, SUPPORTED",
            "3.5.16, TOO_OLD",
            "3.3.13, TOO_OLD",
            "4.0.6, TOO_OLD",
            "2.7.18, TOO_OLD",
            "4.2.0, NEWER",
            "5.0.0-M1, NEWER",
            "unknown, UNKNOWN" })
    void classifiesSpringBootVersions(String version, Result expected) {
        assertThat(EntraSpringBootVersionCheck.check(version)).isEqualTo(expected);
    }

    @Test
    void unknownVersionIsSkipped() {
        assertThat(EntraSpringBootVersionCheck.check(null)).isEqualTo(Result.UNKNOWN);
        assertThatNoException().isThrownBy(() -> new EntraSpringBootVersionCheck(null).initialize(context(null)));
    }

    @Test
    void theBuildLinePasses() {
        assertThat(EntraSpringBootVersionCheck.check(SpringBootVersion.getVersion())).isEqualTo(Result.SUPPORTED);
        assertThatNoException().isThrownBy(() -> new EntraSpringBootVersionCheck().initialize(context(null)));
    }

    @Test
    void springBoot3FailsWithAClearMessage() {
        assertThatIllegalStateException()
                .isThrownBy(() -> new EntraSpringBootVersionCheck("3.5.16").initialize(context(null)))
                .withMessageContaining("needs Spring Boot 4.1.x")
                .withMessageContaining("runs Spring Boot 3.5.16")
                .withMessageContaining("0.7.x")
                .withMessageContaining(EntraSpringBootVersionCheck.ENABLED_PROPERTY + "=false");
    }

    @Test
    void newerLineOnlyWarns() {
        assertThatNoException().isThrownBy(() -> new EntraSpringBootVersionCheck("4.2.0").initialize(context(null)));
    }

    @Test
    void canBeTurnedOff() {
        assertThatNoException()
                .isThrownBy(() -> new EntraSpringBootVersionCheck("3.5.16").initialize(context("false")));
    }

    @Test
    void isRegisteredAsAnInitializer() throws Exception {
        Properties factories = new Properties();
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("META-INF/spring.factories")) {
            assertThat(in).isNotNull();
            factories.load(in);
        }
        assertThat(factories.getProperty("org.springframework.context.ApplicationContextInitializer"))
                .contains(EntraSpringBootVersionCheck.class.getName());
    }

    private static GenericApplicationContext context(String enabled) {
        MockEnvironment environment = new MockEnvironment();
        if (enabled != null) {
            environment.setProperty(EntraSpringBootVersionCheck.ENABLED_PROPERTY, enabled);
        }
        GenericApplicationContext context = new GenericApplicationContext();
        context.setEnvironment(environment);
        return context;
    }
}
