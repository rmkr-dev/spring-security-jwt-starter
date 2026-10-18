package io.github.rmkrdev.entra.security.core.token;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.springframework.util.MultiValueMap;

/**
 * Authenticates with Azure Workload Identity: the Kubernetes service account token that AKS projects
 * into the pod (by default at {@code $AZURE_FEDERATED_TOKEN_FILE}) is sent as a client assertion.
 * <p>
 * The file is re-read on every token request because kubelet rotates it.
 */
public final class WorkloadIdentityCredential implements EntraCredential {

    /** Environment variable set by the AKS workload identity webhook. */
    public static final String TOKEN_FILE_ENV = "AZURE_FEDERATED_TOKEN_FILE";

    private final Path tokenFile;

    public WorkloadIdentityCredential(Path tokenFile) {
        if (tokenFile == null) {
            throw new IllegalArgumentException("A federated token file is required for workload identity");
        }
        this.tokenFile = tokenFile;
    }

    @Override
    public void contribute(MultiValueMap<String, String> form, URI tokenEndpoint, String clientId) {
        form.add("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER);
        form.add("client_assertion", readAssertion());
    }

    @Override
    public String credentialType() {
        return "workload_identity";
    }

    public Path getTokenFile() {
        return tokenFile;
    }

    private String readAssertion() {
        try {
            String assertion = Files.readString(tokenFile, StandardCharsets.UTF_8).trim();
            if (assertion.isEmpty()) {
                throw new IllegalStateException("Federated token file " + tokenFile + " is empty");
            }
            return assertion;
        }
        catch (IOException ex) {
            throw new UncheckedIOException("Unable to read federated token file " + tokenFile, ex);
        }
    }
}
