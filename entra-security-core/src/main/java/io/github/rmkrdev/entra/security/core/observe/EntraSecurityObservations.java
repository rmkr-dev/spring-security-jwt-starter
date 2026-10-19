package io.github.rmkrdev.entra.security.core.observe;

import java.time.Duration;

/**
 * Hooks for optional metrics. The {@link #NO_OP} implementation does nothing, so token validation,
 * Graph lookups and token acquisition behave the same when Micrometer is not in use.
 * <p>
 * Cache hits are not reported: {@link #graphLookup}, {@code tokenAcquisition} and {@link #jwksRefresh}
 * run only when this library actually calls Microsoft Graph, the Entra token endpoint or the JWKS URL.
 */
public interface EntraSecurityObservations {

    EntraSecurityObservations NO_OP = new EntraSecurityObservations() {
    };

    /**
     * A resource-server authentication outcome.
     *
     * @param success {@code true} when the bearer token was accepted
     * @param reason  a bounded label such as {@code none}, {@code expired} or {@code invalid_signature};
     *                never a token, object id or other unbounded value
     */
    default void jwtAuthentication(boolean success, String reason) {
    }

    /**
     * A Microsoft Graph group-overage lookup.
     */
    default void graphLookup(boolean success, Duration duration) {
    }

    /** {@code grant} label of client-credentials token requests. */
    String GRANT_CLIENT_CREDENTIALS = "client_credentials";

    /** {@code grant} label of on-behalf-of (jwt-bearer) token requests. */
    String GRANT_ON_BEHALF_OF = "on_behalf_of";

    /**
     * A client-credentials call to the Entra token endpoint.
     *
     * @param credentialType bounded label: {@code client_secret}, {@code certificate},
     *                       {@code workload_identity} or {@code unknown}
     */
    default void tokenAcquisition(String credentialType, boolean success, Duration duration) {
    }

    /**
     * A call to the Entra token endpoint for any grant. The default forwards client-credentials calls to
     * {@link #tokenAcquisition(String, boolean, Duration)} and ignores the others, so existing
     * implementations keep their meaning.
     *
     * @param grant          {@link #GRANT_CLIENT_CREDENTIALS} or {@link #GRANT_ON_BEHALF_OF}
     * @param credentialType bounded label, as above
     */
    default void tokenAcquisition(String grant, String credentialType, boolean success, Duration duration) {
        if (GRANT_CLIENT_CREDENTIALS.equals(grant)) {
            tokenAcquisition(credentialType, success, duration);
        }
    }

    /**
     * A fetch of the tenant JWKS document.
     */
    default void jwksRefresh(boolean success, Duration duration) {
    }

    /**
     * A remote token check (introspection or userinfo). Cache hits are not reported.
     *
     * @param result bounded label: {@code active}, {@code inactive}, {@code error} or {@code rejected} (circuit
     *               open)
     */
    default void introspection(String result, Duration duration) {
    }

    /**
     * The end of a request's authentication work (validation, role mapping, Graph and authorization).
     */
    default void authDecision(io.github.rmkrdev.entra.security.core.decision.AuthDecision decision) {
    }
}
