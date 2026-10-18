package io.github.rmkrdev.entra.security.core.token;

import java.net.URI;

import org.springframework.util.MultiValueMap;

/**
 * Authenticates with a client secret.
 */
public final class ClientSecretCredential implements EntraCredential {

    private final String clientSecret;

    public ClientSecretCredential(String clientSecret) {
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new IllegalArgumentException("clientSecret must not be blank");
        }
        this.clientSecret = clientSecret;
    }

    @Override
    public void contribute(MultiValueMap<String, String> form, URI tokenEndpoint, String clientId) {
        form.add("client_secret", clientSecret);
    }

    @Override
    public String credentialType() {
        return "client_secret";
    }

    @Override
    public String toString() {
        return "ClientSecretCredential[****]";
    }
}
