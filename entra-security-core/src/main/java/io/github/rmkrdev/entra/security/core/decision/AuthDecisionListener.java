package io.github.rmkrdev.entra.security.core.decision;

/**
 * Receives every {@link AuthDecision}. Called on the request thread, so implementations must be quick and must
 * not throw; exceptions are logged and ignored.
 */
@FunctionalInterface
public interface AuthDecisionListener {

    void onDecision(AuthDecision decision);
}
