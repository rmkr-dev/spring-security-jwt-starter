package io.github.rmkrdev.entra.security.core.introspect;

/**
 * The remote token check could not give a definite answer. Callers fail closed: the token is rejected, and the
 * failure counts towards the circuit breaker.
 */
public class IntrospectionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public IntrospectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
