package io.github.rmkrdev.entra.security.core.cae;

/**
 * Thrown by application code that wants the caller to come back with a token that satisfies {@code claims}, for
 * example after its own check of a critical event. The library never throws it on its own.
 * <p>
 * With {@code entra.security.cae.enabled=true}, callers whose token carries {@code xms_cc=cp1} get
 * {@code 401} with an {@code insufficient_claims} challenge; other callers get a plain {@code 403}, because they
 * cannot answer a challenge.
 */
public class ClaimsChallengeException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String claims;

    /**
     * @param claims      the claims request, as JSON, for example
     *                    {@code {"access_token":{"nbf":{"essential":true,"value":"1700000000"}}}}
     * @param description a short reason, without personal data
     */
    public ClaimsChallengeException(String claims, String description) {
        super(description);
        this.claims = claims;
    }

    public String getClaims() {
        return claims;
    }
}
