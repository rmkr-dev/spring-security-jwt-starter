package io.github.rmkrdev.entra.security.core.token;

import java.util.List;

/**
 * Entra refused an on-behalf-of exchange because the user has to do something first: consent to the
 * downstream scopes ({@code AADSTS65001}), complete MFA or another Conditional Access requirement
 * ({@code interaction_required}, a claims challenge). This API cannot fix it on its own; the client app has
 * to send the user through an interactive sign-in and call again with a new token.
 * <p>
 * The starter turns it into a {@code 403} problem-details response with {@code error=consent_required} or
 * {@code error=interaction_required} and, when Entra sent one, the claims challenge.
 */
public class EntraInteractionRequiredException extends EntraTokenAcquisitionException {

    private static final long serialVersionUID = 1L;

    private static final List<Integer> CONSENT_CODES = List.of(65001, 65004);

    private final String scope;
    private final String suberror;
    private final String claims;
    private final List<Integer> errorCodes;

    public EntraInteractionRequiredException(String message, String error, String suberror, String scope,
            String claims, List<Integer> errorCodes) {
        super(message, error, null);
        this.scope = scope;
        this.suberror = suberror;
        this.claims = claims;
        this.errorCodes = errorCodes == null ? List.of() : List.copyOf(errorCodes);
    }

    /** The downstream scopes that were requested. */
    public String getScope() {
        return scope;
    }

    /** Entra's {@code suberror}, such as {@code consent_required} or {@code basic_action}, if any. */
    public String getSuberror() {
        return suberror;
    }

    /** The claims challenge to pass to the client for a step-up sign-in, or {@code null}. */
    public String getClaims() {
        return claims;
    }

    /** The {@code AADSTS} error codes, such as {@code 65001}. */
    public List<Integer> getErrorCodes() {
        return errorCodes;
    }

    /** Whether the user (or an admin) has not consented to the downstream scopes. */
    public boolean isConsentRequired() {
        return "consent_required".equals(getError()) || "consent_required".equals(suberror)
                || errorCodes.stream().anyMatch(CONSENT_CODES::contains);
    }

    /** {@code consent_required} or {@code interaction_required}, for problem-details bodies. */
    public String getProblemErrorCode() {
        return isConsentRequired() ? "consent_required" : "interaction_required";
    }
}
