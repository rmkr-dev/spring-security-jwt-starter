package io.github.rmkrdev.entra.security.autoconfigure.metrics;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class MicrometerTokenAcquisitionTest {

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final MicrometerEntraSecurityObservations observations = new MicrometerEntraSecurityObservations(registry);

    @Test
    void tokenAcquisitionsAreTaggedWithTheGrant() {
        observations.tokenAcquisition("client_secret", true, Duration.ofMillis(5));
        observations.tokenAcquisition(EntraSecurityObservations.GRANT_ON_BEHALF_OF, "workload_identity", false,
                Duration.ofMillis(7));

        assertThat(registry.get(MicrometerEntraSecurityObservations.TOKEN_ACQUISITIONS)
                .tags("grant", "client_credentials", "credential", "client_secret", "result", "success").timer()
                .count()).isEqualTo(1);
        assertThat(registry.get(MicrometerEntraSecurityObservations.TOKEN_ACQUISITIONS)
                .tags("grant", "on_behalf_of", "credential", "workload_identity", "result", "failure").timer()
                .count()).isEqualTo(1);
    }

    @Test
    void unknownGrantLabelsAreBounded() {
        observations.tokenAcquisition("user-123", "client_secret", true, Duration.ZERO);

        assertThat(registry.get(MicrometerEntraSecurityObservations.TOKEN_ACQUISITIONS).tags("grant", "unknown")
                .timer().count()).isEqualTo(1);
    }
}
