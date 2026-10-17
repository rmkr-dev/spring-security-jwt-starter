package io.github.rmkrdev.entra.security.autoconfigure;

import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;

import org.springframework.core.env.Environment;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.Credential;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.CredentialType;
import io.github.rmkrdev.entra.security.core.token.ClientCertificateCredential;
import io.github.rmkrdev.entra.security.core.token.ClientCredentialsTokenProvider;
import io.github.rmkrdev.entra.security.core.token.ClientSecretCredential;
import io.github.rmkrdev.entra.security.core.token.EntraCredential;
import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;
import io.github.rmkrdev.entra.security.core.token.WorkloadIdentityCredential;

/**
 * Creates {@link EntraTokenProvider}s from {@code entra.security.credential}-style configuration.
 * <p>
 * For workload identity, the values injected by the AKS webhook ({@code AZURE_CLIENT_ID},
 * {@code AZURE_TENANT_ID}, {@code AZURE_FEDERATED_TOKEN_FILE}, {@code AZURE_AUTHORITY_HOST}) are used
 * when not configured explicitly.
 */
public class EntraTokenProviders {

    private final EntraSecurityProperties properties;
    private final Environment environment;
    private final RestClient restClient;
    private final Clock clock;

    public EntraTokenProviders(EntraSecurityProperties properties, Environment environment) {
        this(properties, environment, defaultRestClient(properties), Clock.systemUTC());
    }

    public EntraTokenProviders(EntraSecurityProperties properties, Environment environment, RestClient restClient,
            Clock clock) {
        this.properties = properties;
        this.environment = environment;
        this.restClient = restClient;
        this.clock = clock;
    }

    static RestClient defaultRestClient(EntraSecurityProperties properties) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(properties.getHttp().getConnectTimeout());
        factory.setReadTimeout(properties.getHttp().getReadTimeout());
        return RestClient.builder().requestFactory(factory).build();
    }

    /** The provider for this API's own credential ({@code entra.security.credential}). */
    public EntraTokenProvider applicationTokenProvider() {
        return create(properties.getCredential());
    }

    /**
     * A provider for the given credential, falling back to {@code entra.security.credential} when its
     * type is {@code none}.
     */
    public EntraTokenProvider create(Credential credential) {
        Credential effective = credential.getType() == CredentialType.NONE ? properties.getCredential() : credential;
        if (effective.getType() == CredentialType.NONE) {
            throw new IllegalStateException("No Entra credential configured: set entra.security.credential.type");
        }
        boolean workload = effective.getType() == CredentialType.WORKLOAD_IDENTITY;
        String tenantId = firstText(effective.getTenantId(), workload ? env("AZURE_TENANT_ID") : null,
                properties.getTenantId());
        String clientId = firstText(effective.getClientId(), workload ? env("AZURE_CLIENT_ID") : null,
                properties.getClientId());
        String authority = firstText(workload ? env("AZURE_AUTHORITY_HOST") : null,
                properties.getAuthorityHost().toString());
        URI tokenEndpoint = ClientCredentialsTokenProvider.tokenEndpoint(URI.create(authority), tenantId);
        return new ClientCredentialsTokenProvider(tokenEndpoint, clientId, credential(effective), restClient,
                properties.getCache().getTokenRefreshSkew(), clock);
    }

    private EntraCredential credential(Credential credential) {
        switch (credential.getType()) {
            case CLIENT_SECRET:
                return new ClientSecretCredential(credential.getClientSecret());
            case CERTIFICATE:
                return ClientCertificateCredential.fromFile(Path.of(credential.getCertificatePath()),
                        credential.getCertificatePassword());
            case WORKLOAD_IDENTITY:
                String file = firstText(credential.getFederatedTokenFile(),
                        env(WorkloadIdentityCredential.TOKEN_FILE_ENV));
                if (file == null) {
                    throw new IllegalStateException("Workload identity needs credential.federated-token-file or "
                            + WorkloadIdentityCredential.TOKEN_FILE_ENV);
                }
                return new WorkloadIdentityCredential(Path.of(file));
            default:
                throw new IllegalStateException("Unsupported credential type " + credential.getType());
        }
    }

    private String env(String name) {
        return environment.getProperty(name);
    }

    private static String firstText(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value;
            }
        }
        return null;
    }
}
