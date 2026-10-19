package io.github.rmkrdev.entra.security.core.introspect;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * A small circuit breaker for the remote token check. After {@code failureThreshold} consecutive failures it opens
 * for {@code openDuration}: calls are refused without reaching the authority, so tokens are rejected (fail closed)
 * instead of piling up behind a slow or broken endpoint. After that one trial call is let through; success closes
 * the circuit, failure opens it again.
 */
public final class IntrospectionCircuitBreaker {

    /** Circuit state. */
    public enum State {
        CLOSED, OPEN, HALF_OPEN
    }

    private final int failureThreshold;
    private final Duration openDuration;
    private final Clock clock;
    private int consecutiveFailures;
    private Instant openUntil;
    private boolean trialInFlight;

    public IntrospectionCircuitBreaker(int failureThreshold, Duration openDuration, Clock clock) {
        if (failureThreshold < 1) {
            throw new IllegalArgumentException("failureThreshold must be at least 1");
        }
        this.failureThreshold = failureThreshold;
        this.openDuration = openDuration;
        this.clock = clock;
    }

    /** Whether a call may go to the authority now. */
    public synchronized boolean tryAcquire() {
        if (openUntil == null) {
            return true;
        }
        if (clock.instant().isBefore(openUntil) || trialInFlight) {
            return false;
        }
        trialInFlight = true;
        return true;
    }

    /** Records a definite answer (active or inactive). */
    public synchronized void onSuccess() {
        consecutiveFailures = 0;
        openUntil = null;
        trialInFlight = false;
    }

    /** Records a failed call. */
    public synchronized void onFailure() {
        consecutiveFailures++;
        if (trialInFlight || consecutiveFailures >= failureThreshold) {
            openUntil = clock.instant().plus(openDuration);
        }
        trialInFlight = false;
    }

    public synchronized State state() {
        if (openUntil == null) {
            return State.CLOSED;
        }
        return clock.instant().isBefore(openUntil) && !trialInFlight ? State.OPEN : State.HALF_OPEN;
    }
}
