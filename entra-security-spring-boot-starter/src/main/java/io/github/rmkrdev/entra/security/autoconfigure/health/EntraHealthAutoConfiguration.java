package io.github.rmkrdev.entra.security.autoconfigure.health;

import java.net.URI;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.rmkrdev.entra.security.autoconfigure.EntraEndpoints;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityAutoConfiguration;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties;
import io.github.rmkrdev.entra.security.autoconfigure.EntraTokenProviders;

/**
 * Actuator health for the tenant JWKS and, when group overage is enabled, Microsoft Graph.
 * <p>
 * Skipped entirely when {@code spring-boot-actuator} is not on the classpath. Bean names are
 * {@code entraJwksHealthIndicator} and {@code entraGraphHealthIndicator}, which Actuator exposes as
 * {@code entraJwks} and {@code entraGraph}. The Graph indicator is omitted when overage is disabled
 * so it cannot fail the application.
 */
@AutoConfiguration(after = EntraSecurityAutoConfiguration.class)
@ConditionalOnClass(HealthIndicator.class)
@ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
public class EntraHealthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(name = "entraJwksHealthIndicator")
    @ConditionalOnBean(name = "entraJwkSource")
    @ConditionalOnExpression("'${entra.security.validation.mode:jwks}'.toLowerCase() != 'introspection'")
    public HealthIndicator entraJwksHealthIndicator(
            @Qualifier("entraJwkSource") JWKSource<SecurityContext> entraJwkSource) {
        return new EntraJwksHealthIndicator(entraJwkSource);
    }

    @Bean
    @ConditionalOnMissingBean(name = "entraGraphHealthIndicator")
    @ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "graph.overage-enabled",
            havingValue = "true")
    @ConditionalOnBean(EntraTokenProviders.class)
    public HealthIndicator entraGraphHealthIndicator(EntraSecurityProperties properties,
            EntraTokenProviders tokenProviders, ObjectProvider<EntraEndpoints> endpoints) {
        EntraSecurityProperties.Graph graph = properties.getGraph();
        URI graphBaseUrl = endpoints.getIfAvailable(() -> EntraEndpoints.of(properties)).graphBaseUrl();
        return new EntraGraphHealthIndicator(tokenProviders.applicationTokenProvider(),
                EntraTokenProviders.defaultRestClient(properties), graphBaseUrl, graph.getScope());
    }
}
