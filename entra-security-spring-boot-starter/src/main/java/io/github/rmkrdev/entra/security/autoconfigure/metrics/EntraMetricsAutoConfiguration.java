package io.github.rmkrdev.entra.security.autoconfigure.metrics;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityAutoConfiguration;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Micrometer meters for JWT authentication, JWKS refresh, Graph overage lookups and outbound token
 * acquisition. Absent when {@code micrometer-core} is not on the classpath, so applications that do
 * not use metrics are unchanged.
 */
@AutoConfiguration(after = EntraSecurityAutoConfiguration.class, afterName = {
        "org.springframework.boot.actuate.autoconfigure.metrics.CompositeMeterRegistryAutoConfiguration",
        "org.springframework.boot.actuate.autoconfigure.metrics.MetricsAutoConfiguration" })
@ConditionalOnClass(MeterRegistry.class)
@ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
public class EntraMetricsAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(EntraSecurityObservations.class)
    public EntraSecurityObservations entraSecurityObservations(ObjectProvider<MeterRegistry> registries) {
        return new LazyMicrometerEntraSecurityObservations(registries);
    }
}
