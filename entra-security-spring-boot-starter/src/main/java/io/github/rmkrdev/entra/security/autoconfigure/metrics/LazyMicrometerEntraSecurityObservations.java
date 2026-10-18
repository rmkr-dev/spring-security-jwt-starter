package io.github.rmkrdev.entra.security.autoconfigure.metrics;

import java.time.Duration;

import org.springframework.beans.factory.ObjectProvider;

import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Resolves the {@link MeterRegistry} on first use so auto-configuration order cannot drop the meters.
 * Calls made before a registry exists are ignored and do not stick.
 */
final class LazyMicrometerEntraSecurityObservations implements EntraSecurityObservations {

    private final ObjectProvider<MeterRegistry> registries;
    private volatile EntraSecurityObservations delegate;

    LazyMicrometerEntraSecurityObservations(ObjectProvider<MeterRegistry> registries) {
        this.registries = registries;
    }

    @Override
    public void jwtAuthentication(boolean success, String reason) {
        delegate().jwtAuthentication(success, reason);
    }

    @Override
    public void graphLookup(boolean success, Duration duration) {
        delegate().graphLookup(success, duration);
    }

    @Override
    public void tokenAcquisition(String credentialType, boolean success, Duration duration) {
        delegate().tokenAcquisition(credentialType, success, duration);
    }

    @Override
    public void tokenAcquisition(String grant, String credentialType, boolean success, Duration duration) {
        delegate().tokenAcquisition(grant, credentialType, success, duration);
    }

    @Override
    public void jwksRefresh(boolean success, Duration duration) {
        delegate().jwksRefresh(success, duration);
    }

    private EntraSecurityObservations delegate() {
        EntraSecurityObservations current = delegate;
        if (current != null) {
            return current;
        }
        MeterRegistry registry = registries.getIfAvailable();
        if (registry == null) {
            return EntraSecurityObservations.NO_OP;
        }
        synchronized (this) {
            if (delegate == null) {
                delegate = new MicrometerEntraSecurityObservations(registry);
            }
            return delegate;
        }
    }
}
