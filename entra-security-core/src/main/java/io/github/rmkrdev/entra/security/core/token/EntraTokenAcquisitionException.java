package io.github.rmkrdev.entra.security.core.token;

/**
 * Raised when an access token could not be acquired from Entra ID.
 */
public class EntraTokenAcquisitionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String error;

    public EntraTokenAcquisitionException(String message, String error, Throwable cause) {
        super(message, cause);
        this.error = error;
    }

    /**
     * The OAuth error code returned by Entra, such as {@code invalid_client}, if any.
     */
    public String getError() {
        return error;
    }
}
