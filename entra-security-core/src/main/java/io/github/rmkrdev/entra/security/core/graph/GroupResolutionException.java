package io.github.rmkrdev.entra.security.core.graph;

/**
 * Raised when group memberships could not be read from Microsoft Graph.
 */
public class GroupResolutionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public GroupResolutionException(String message) {
        super(message);
    }

    public GroupResolutionException(String message, Throwable cause) {
        super(message, cause);
    }
}
