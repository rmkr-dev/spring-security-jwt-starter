package io.github.rmkrdev.entra.security.autoconfigure.metrics;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.boot.actuate.autoconfigure.metrics.MeterRegistryCustomizer;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.core.instrument.distribution.DistributionStatisticConfig;
import io.micrometer.datadog.DatadogMeterRegistry;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

/**
 * Backend-specific tuning for the {@code entra.security.*} meters. Datadog is the documented backend:
 * Spring Boot creates the registry from {@code management.datadog.metrics.export.*}; this adds client-side
 * percentiles. Prometheus is opt-in: unless {@code entra.security.monitoring.prometheus.enabled=true}, the
 * entra meters are kept out of a Prometheus registry.
 */
@AutoConfiguration(before = EntraMetricsAutoConfiguration.class)
@ConditionalOnClass({ MeterRegistry.class, MeterRegistryCustomizer.class })
@ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(EntraSecurityProperties.class)
public class EntraMonitoringAutoConfiguration {

    static final String PREFIX = "entra.security.";

    @Bean
    MeterRegistryCustomizer<MeterRegistry> entraMeterTags(EntraSecurityProperties properties) {
        return registry -> registry.config().meterFilter(commonTags(properties.getMonitoring().getTags()));
    }

    static MeterFilter commonTags(Map<String, String> tags) {
        List<Tag> list = new ArrayList<>();
        tags.forEach((k, v) -> list.add(Tag.of(k, v)));
        return new MeterFilter() {
            @Override
            public Meter.Id map(Meter.Id id) {
                return list.isEmpty() || !id.getName().startsWith(PREFIX) ? id : id.withTags(list);
            }
        };
    }

    static MeterFilter percentiles() {
        return new MeterFilter() {
            @Override
            public DistributionStatisticConfig configure(Meter.Id id, DistributionStatisticConfig config) {
                if (!id.getName().startsWith(PREFIX) || id.getType() != Meter.Type.TIMER) {
                    return config;
                }
                return DistributionStatisticConfig.builder().percentiles(0.5, 0.95, 0.99)
                        .percentilesHistogram(false).build().merge(config);
            }
        };
    }

    static MeterFilter denyEntra() {
        return MeterFilter.deny(id -> id.getName().startsWith(PREFIX));
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(DatadogMeterRegistry.class)
    static class Datadog {

        @Bean
        MeterRegistryCustomizer<DatadogMeterRegistry> entraDatadogPercentiles(EntraSecurityProperties properties) {
            return registry -> {
                if (properties.getMonitoring().getDatadog().isPercentiles()) {
                    registry.config().meterFilter(percentiles());
                }
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(PrometheusMeterRegistry.class)
    static class Prometheus {

        @Bean
        MeterRegistryCustomizer<PrometheusMeterRegistry> entraPrometheusOptIn(EntraSecurityProperties properties) {
            return registry -> {
                if (!properties.getMonitoring().getPrometheus().isEnabled()) {
                    registry.config().meterFilter(denyEntra());
                }
            };
        }
    }

}
