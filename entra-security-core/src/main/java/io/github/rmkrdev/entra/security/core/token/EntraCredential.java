package io.github.rmkrdev.entra.security.core.token;

import java.net.URI;

import org.springframework.util.MultiValueMap;

/**
 * How a confidential client proves its identity on the token endpoint.
 */
public interface EntraCredential {

    String CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /**
     * Adds the client authentication parameters to a token request form.
     *
     * @param form          the form being sent
     * @param tokenEndpoint the token endpoint (the audience of client assertions)
     * @param clientId      the client id making the request
     */
    void contribute(MultiValueMap<String, String> form, URI tokenEndpoint, String clientId);

    /**
     * Bounded label for metrics: {@code client_secret}, {@code certificate} or {@code workload_identity}.
     */
    default String credentialType() {
        return "unknown";
    }
}
