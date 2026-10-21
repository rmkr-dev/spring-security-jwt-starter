package io.github.rmkrdev.entra.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.http.converter.autoconfigure.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.rmkrdev.entra.security.autoconfigure.health.EntraHealthAutoConfiguration;
import io.github.rmkrdev.entra.security.autoconfigure.metrics.EntraMetricsAutoConfiguration;
import io.github.rmkrdev.entra.security.core.jwt.JwtAuthenticationOutcomes;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class EntraObservabilityAutoConfigurationTest {

    private static final String TENANT = "entra.security.tenant-id=11111111-1111-1111-1111-111111111111";
    private static final String CLIENT = "entra.security.client-id=22222222-2222-2222-2222-222222222222";

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EntraSecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class,
                    EntraHealthAutoConfiguration.class, EntraMetricsAutoConfiguration.class,
                    SecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class, UserDetailsServiceAutoConfiguration.class,
                    OAuth2ResourceServerAutoConfiguration.class, WebMvcAutoConfiguration.class,
                    JacksonAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class))
            .withUserConfiguration(MetricsConfiguration.class)
            .withPropertyValues(TENANT, CLIENT);

    @Test
    void jwksHealthAndMetricsArePresentWithoutGraph() {
        runner.run(context -> {
            assertThat(context).hasBean("entraJwksHealthIndicator");
            assertThat(context).doesNotHaveBean("entraGraphHealthIndicator");
            context.getBean(EntraSecurityObservations.class).jwtAuthentication(true, JwtAuthenticationOutcomes.NONE);
            context.getBean(EntraSecurityObservations.class).jwtAuthentication(false, "raw oid " + "should-not-leak");
            MeterRegistry registry = context.getBean(MeterRegistry.class);
            assertThat(registry.get("entra.security.jwt.authentications").tag("result", "success").tag("reason", "none")
                    .counter().count()).isEqualTo(1);
            assertThat(registry.get("entra.security.jwt.authentications").tag("result", "failure")
                    .tag("reason", "invalid_token").counter().count()).isEqualTo(1);
            assertThat(registry.getMeters().stream().flatMap(meter -> meter.getId().getTags().stream())
                    .noneMatch(tag -> tag.getValue().contains("should-not-leak"))).isTrue();
        });
    }

    @Test
    void graphHealthAppearsWhenOverageIsEnabled() {
        runner.withPropertyValues("entra.security.graph.overage-enabled=true",
                "entra.security.credential.type=client-secret", "entra.security.credential.client-secret=x")
                .run(context -> assertThat(context).hasBean("entraGraphHealthIndicator"));
    }

    @Test
    void healthAndMetricsBackOffWhenSecurityIsDisabled() {
        runner.withPropertyValues("entra.security.enabled=false").run(context -> {
            assertThat(context).doesNotHaveBean("entraJwksHealthIndicator");
            assertThat(context).doesNotHaveBean(EntraSecurityObservations.class);
        });
    }

    @Test
    void customJwksIndicatorIsKept() {
        runner.withUserConfiguration(CustomJwks.class).run(context -> {
            assertThat(context).hasBean("entraJwksHealthIndicator");
            assertThat(context.getBean("entraJwksHealthIndicator", HealthIndicator.class).health().getDetails())
                    .containsEntry("custom", true);
        });
    }

    @Test
    void metricsWithoutARegistryDoNotFailTheContext() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(EntraSecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class,
                        EntraMetricsAutoConfiguration.class, SecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class,
                        UserDetailsServiceAutoConfiguration.class, OAuth2ResourceServerAutoConfiguration.class,
                        WebMvcAutoConfiguration.class, JacksonAutoConfiguration.class,
                        HttpMessageConvertersAutoConfiguration.class))
                .withPropertyValues(TENANT, CLIENT)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(EntraSecurityObservations.class);
                    context.getBean(EntraSecurityObservations.class).jwksRefresh(true, Duration.ofMillis(1));
                    assertThat(context).doesNotHaveBean(MeterRegistry.class);
                });
    }

    @Test
    void autoConfigurationMetadataKeepsActuatorAndMicrometerOptional() throws IOException {
        Properties metadata = new Properties();
        try (InputStream in = getClass().getClassLoader()
                .getResourceAsStream("META-INF/spring-autoconfigure-metadata.properties")) {
            assertThat(in).isNotNull();
            metadata.load(in);
        }
        assertThat(metadata.getProperty(
                "io.github.rmkrdev.entra.security.autoconfigure.health.EntraHealthAutoConfiguration.ConditionalOnClass"))
                .contains("org.springframework.boot.health.contributor.HealthIndicator");
        assertThat(metadata.getProperty(
                "io.github.rmkrdev.entra.security.autoconfigure.metrics.EntraMetricsAutoConfiguration.ConditionalOnClass"))
                .contains("io.micrometer.core.instrument.MeterRegistry");
    }

    @Configuration(proxyBeanMethods = false)
    static class MetricsConfiguration {

        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomJwks {

        @Bean(name = "entraJwksHealthIndicator")
        HealthIndicator entraJwksHealthIndicator() {
            return () -> Health.up().withDetail("custom", true).build();
        }
    }
}
