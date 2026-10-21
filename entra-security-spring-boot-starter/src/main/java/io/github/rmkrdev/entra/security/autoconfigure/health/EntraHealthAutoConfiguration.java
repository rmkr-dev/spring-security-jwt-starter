package io.github.rmkrdev.entra.security.autoconfigure.health;

import java.net.URI;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.ReactiveHealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;

import io.github.rmkrdev.entra.security.autoconfigure.OnNotReactiveWebApplicationCondition;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.rmkrdev.entra.security.autoconfigure.EntraEndpoints;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityAutoConfiguration;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties;
import io.github.rmkrdev.entra.security.autoconfigure.EntraTokenProviders;

/**
 * Actuator health for the tenant JWKS and, when group overage is enabled, Microsoft Graph.
 * <p>
 * Skipped entirely when {@code spring-boot-health} is not on the classpath. Servlet applications get
 * {@code entraJwksHealthIndicator} and {@code entraGraphHealthIndicator}. WebFlux applications get the
 * reactive equivalents. Actuator exposes both as {@code entraJwks} and {@code entraGraph}. The Graph
 * indicator is omitted when overage is disabled so it cannot fail the application.
 */
@AutoConfiguration(after = EntraSecurityAutoConfiguration.class)
@ConditionalOnClass(HealthIndicator.class)
@ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
public class EntraHealthAutoConfiguration {

    @Bean
    @Conditional(OnNotReactiveWebApplicationCondition.class)
    @ConditionalOnMissingBean(name = "entraJwksHealthIndicator")
    @ConditionalOnBean(name = "entraJwkSource")
    @ConditionalOnExpression("'${entra.security.validation.mode:jwks}'.toLowerCase() != 'introspection'")
    public HealthIndicator entraJwksHealthIndicator(
            @Qualifier("entraJwkSource") JWKSource<SecurityContext> entraJwkSource) {
        return new EntraJwksHealthIndicator(entraJwkSource);
    }

    @Bean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    @ConditionalOnMissingBean(name = "entraJwksReactiveHealthIndicator")
    @ConditionalOnBean(name = "entraJwkSource")
    @ConditionalOnExpression("'${entra.security.validation.mode:jwks}'.toLowerCase() != 'introspection'")
    public ReactiveHealthIndicator entraJwksReactiveHealthIndicator(
            @Qualifier("entraJwkSource") JWKSource<SecurityContext> entraJwkSource) {
        return new EntraJwksReactiveHealthIndicator(entraJwkSource);
    }

    @Bean
    @Conditional(OnNotReactiveWebApplicationCondition.class)
    @ConditionalOnMissingBean(name = "entraGraphHealthIndicator")
    @ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "graph.overage-enabled",
            havingValue = "true")
    @ConditionalOnBean(EntraTokenProviders.class)
    public HealthIndicator entraGraphHealthIndicator(EntraSecurityProperties properties,
            EntraTokenProviders tokenProviders, ObjectProvider<EntraEndpoints> endpoints) {
        return graphIndicator(properties, tokenProviders, endpoints);
    }

    @Bean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    @ConditionalOnMissingBean(name = "entraGraphReactiveHealthIndicator")
    @ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "graph.overage-enabled",
            havingValue = "true")
    @ConditionalOnBean(EntraTokenProviders.class)
    public ReactiveHealthIndicator entraGraphReactiveHealthIndicator(EntraSecurityProperties properties,
            EntraTokenProviders tokenProviders, ObjectProvider<EntraEndpoints> endpoints) {
        EntraSecurityProperties.Graph graph = properties.getGraph();
        URI graphBaseUrl = endpoints.getIfAvailable(() -> EntraEndpoints.of(properties)).graphBaseUrl();
        return new EntraGraphReactiveHealthIndicator(tokenProviders.applicationTokenProvider(),
                EntraTokenProviders.defaultRestClient(properties), graphBaseUrl, graph.getScope());
    }

    private static HealthIndicator graphIndicator(EntraSecurityProperties properties,
            EntraTokenProviders tokenProviders, ObjectProvider<EntraEndpoints> endpoints) {
        EntraSecurityProperties.Graph graph = properties.getGraph();
        URI graphBaseUrl = endpoints.getIfAvailable(() -> EntraEndpoints.of(properties)).graphBaseUrl();
        return new EntraGraphHealthIndicator(tokenProviders.applicationTokenProvider(),
                EntraTokenProviders.defaultRestClient(properties), graphBaseUrl, graph.getScope());
    }
}
