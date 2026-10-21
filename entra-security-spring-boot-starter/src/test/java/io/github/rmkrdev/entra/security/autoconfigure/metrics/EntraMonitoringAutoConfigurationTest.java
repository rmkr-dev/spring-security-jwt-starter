package io.github.rmkrdev.entra.security.autoconfigure.metrics;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.micrometer.metrics.autoconfigure.MeterRegistryCustomizer;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import io.micrometer.core.instrument.Clock;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.datadog.DatadogConfig;
import io.micrometer.datadog.DatadogMeterRegistry;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

class EntraMonitoringAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EntraMonitoringAutoConfiguration.class))
            .withPropertyValues("entra.security.tenant-id=11111111-1111-1111-1111-111111111111",
                    "entra.security.client-id=22222222-2222-2222-2222-222222222222");

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private static <T extends MeterRegistry> void customize(org.springframework.context.ApplicationContext ctx,
            Class<T> type, T registry) {
        ((MeterRegistryCustomizer) ctx.getBean("entraMeterTags")).customize(registry);
        String own = type == DatadogMeterRegistry.class ? "entraDatadogPercentiles"
                : type == PrometheusMeterRegistry.class ? "entraPrometheusOptIn" : null;
        if (own != null) {
            ((MeterRegistryCustomizer) ctx.getBean(own)).customize(registry);
        }
    }

    @Test
    void commonTagsOnlyTouchEntraMeters() {
        runner.withPropertyValues("entra.security.monitoring.tags.service=orders-api").run(ctx -> {
            SimpleMeterRegistry registry = new SimpleMeterRegistry();
            customize(ctx, SimpleMeterRegistry.class, registry);
            registry.counter("entra.security.auth.failures").increment();
            registry.counter("http.other").increment();
            assertThat(registry.get("entra.security.auth.failures").counter().getId().getTag("service"))
                    .isEqualTo("orders-api");
            assertThat(registry.get("http.other").counter().getId().getTag("service")).isNull();
        });
    }

    @Test
    void prometheusIsOptIn() {
        runner.run(ctx -> {
            PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
            customize(ctx, PrometheusMeterRegistry.class, registry);
            registry.counter("entra.security.auth.failures").increment();
            registry.counter("other").increment();
            assertThat(registry.scrape()).doesNotContain("entra_security").contains("other_total");
        });
        runner.withPropertyValues("entra.security.monitoring.prometheus.enabled=true").run(ctx -> {
            PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
            customize(ctx, PrometheusMeterRegistry.class, registry);
            registry.counter("entra.security.auth.failures").increment();
            assertThat(registry.scrape()).contains("entra_security_auth_failures_total");
        });
    }

    @Test
    void datadogGetsClientSidePercentilesForEntraTimers() {
        DatadogConfig config = new DatadogConfig() {
            @Override
            public String get(String key) {
                return null;
            }

            @Override
            public String apiKey() {
                return "test";
            }

            @Override
            public boolean enabled() {
                return false;
            }

            @Override
            public Duration step() {
                return Duration.ofMinutes(1);
            }
        };
        runner.run(ctx -> {
            DatadogMeterRegistry registry = new DatadogMeterRegistry(config, Clock.SYSTEM);
            customize(ctx, DatadogMeterRegistry.class, registry);
            Timer timer = registry.timer("entra.security.auth.duration");
            timer.record(Duration.ofMillis(2));
            assertThat(timer.takeSnapshot().percentileValues()).hasSize(3);
            assertThat(registry.timer("other.timer").takeSnapshot().percentileValues()).isEmpty();
            registry.close();
        });
        runner.withPropertyValues("entra.security.monitoring.datadog.percentiles=false").run(ctx -> {
            DatadogMeterRegistry registry = new DatadogMeterRegistry(config, Clock.SYSTEM);
            customize(ctx, DatadogMeterRegistry.class, registry);
            assertThat(registry.timer("entra.security.auth.duration").takeSnapshot().percentileValues()).isEmpty();
            registry.close();
        });
    }

    @Test
    void backendCustomizersAbsentWithoutRegistries() {
        runner.withClassLoader(new FilteredClassLoader(DatadogMeterRegistry.class, PrometheusMeterRegistry.class))
                .run(ctx -> {
                    assertThat(ctx).hasBean("entraMeterTags");
                    assertThat(ctx).doesNotHaveBean("entraDatadogPercentiles");
                    assertThat(ctx).doesNotHaveBean("entraPrometheusOptIn");
                    assertThat(EntraMonitoringAutoConfiguration.commonTags(Map.of())
                            .map(new SimpleMeterRegistry().counter("entra.security.x").getId()).getTags()).isEmpty();
                });
    }
}
