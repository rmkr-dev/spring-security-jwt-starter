package io.github.rmkrdev.entra.security.autoconfigure;

import java.net.URI;
import java.nio.file.Path;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.springframework.core.env.Environment;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.Credential;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.CredentialType;
import io.github.rmkrdev.entra.security.autoconfigure.keyvault.KeyVaultCredentialFactory;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.token.ClientCertificateCredential;
import io.github.rmkrdev.entra.security.core.token.ClientCredentialsTokenProvider;
import io.github.rmkrdev.entra.security.core.token.ClientSecretCredential;
import io.github.rmkrdev.entra.security.core.token.EntraCredential;
import io.github.rmkrdev.entra.security.core.token.EntraOnBehalfOfTokenProvider;
import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;
import io.github.rmkrdev.entra.security.core.token.OnBehalfOfTokenProvider;
import io.github.rmkrdev.entra.security.core.token.WorkloadIdentityCredential;

/**
 * Creates {@link EntraTokenProvider}s from {@code entra.security.credential}-style configuration.
 * <p>
 * For workload identity, the values injected by the AKS webhook ({@code AZURE_CLIENT_ID},
 * {@code AZURE_TENANT_ID}, {@code AZURE_FEDERATED_TOKEN_FILE}, {@code AZURE_AUTHORITY_HOST}) are used
 * when not configured explicitly.
 */
public class EntraTokenProviders {

    private static final Map<Duration, HttpClient> CLIENTS = new ConcurrentHashMap<>();
    private static final Executor REFRESHER = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "entra-token-refresh");
        thread.setDaemon(true);
        return thread;
    });

    private final EntraSecurityProperties properties;
    private final Environment environment;
    private final RestClient restClient;
    private final Clock clock;
    private final EntraSecurityObservations observations;
    private final KeyVaultCredentialFactory keyVaultCredentials;
    private final EntraEndpoints endpoints;

    public EntraTokenProviders(EntraSecurityProperties properties, Environment environment) {
        this(properties, environment, defaultRestClient(properties), Clock.systemUTC());
    }

    public EntraTokenProviders(EntraSecurityProperties properties, Environment environment, RestClient restClient,
            Clock clock) {
        this(properties, environment, restClient, clock, EntraSecurityObservations.NO_OP);
    }

    /**
     * @param observations token-acquisition hook forwarded to each provider; {@code null} is a no-op
     */
    public EntraTokenProviders(EntraSecurityProperties properties, Environment environment, RestClient restClient,
            Clock clock, EntraSecurityObservations observations) {
        this(properties, environment, restClient, clock, observations, null);
    }

    /**
     * @param observations        token-acquisition hook forwarded to each provider; {@code null} is a no-op
     * @param keyVaultCredentials creates {@code key-vault-certificate} credentials; {@code null} when the Azure
     *                            SDK is not on the classpath, in which case configuring that type fails here
     */
    public EntraTokenProviders(EntraSecurityProperties properties, Environment environment, RestClient restClient,
            Clock clock, EntraSecurityObservations observations, KeyVaultCredentialFactory keyVaultCredentials) {
        this(properties, environment, restClient, clock, observations, keyVaultCredentials, null);
    }

    /**
     * @param endpoints the resolved authority endpoints; {@code null} resolves them from {@code properties}
     *                  without OIDC discovery
     */
    public EntraTokenProviders(EntraSecurityProperties properties, Environment environment, RestClient restClient,
            Clock clock, EntraSecurityObservations observations, KeyVaultCredentialFactory keyVaultCredentials,
            EntraEndpoints endpoints) {
        this.properties = properties;
        this.endpoints = endpoints != null ? endpoints : EntraEndpoints.of(properties);
        this.environment = environment;
        this.restClient = restClient;
        this.clock = clock;
        this.observations = observations == null ? EntraSecurityObservations.NO_OP : observations;
        this.keyVaultCredentials = keyVaultCredentials;
        if (keyVaultCredentials == null && usesKeyVault(properties)) {
            throw new IllegalStateException(KEY_VAULT_MISSING);
        }
    }

    static final String KEY_VAULT_MISSING = "credential.type=key-vault-certificate needs the Azure SDK on the "
            + "classpath: add com.azure:azure-identity and com.azure:azure-security-keyvault-secrets (or "
            + "com.azure:azure-security-keyvault-certificates)";

    private static boolean usesKeyVault(EntraSecurityProperties properties) {
        return properties.getCredential().getType() == CredentialType.KEY_VAULT_CERTIFICATE
                || properties.getOutbound().getClients().values().stream()
                        .anyMatch(c -> c.getCredential().getType() == CredentialType.KEY_VAULT_CERTIFICATE);
    }

    /** HTTP client that uses {@code entra.security.http} connect and read timeouts. */
    public static RestClient defaultRestClient(EntraSecurityProperties properties) {
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(
                pooledHttpClient(properties.getHttp().getConnectTimeout()));
        factory.setReadTimeout(properties.getHttp().getReadTimeout());
        return RestClient.builder().requestFactory(factory).build();
    }

    /**
     * The shared JDK HTTP client for a connect timeout. One client per timeout keeps a single keep-alive
     * connection pool for the token endpoint, Graph, JWKS discovery and introspection, instead of a new TCP and
     * TLS handshake per call.
     */
    public static HttpClient pooledHttpClient(Duration connectTimeout) {
        return CLIENTS.computeIfAbsent(connectTimeout, timeout -> HttpClient.newBuilder()
                .connectTimeout(timeout)
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build());
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
        Credential effective = effective(credential);
        boolean workload = effective.getType() == CredentialType.WORKLOAD_IDENTITY;
        String clientId = firstText(effective.getClientId(), workload ? env("AZURE_CLIENT_ID") : null,
                properties.getClientId());
        ClientCredentialsTokenProvider provider = new ClientCredentialsTokenProvider(tokenEndpoint(effective),
                clientId, credential(effective), restClient, properties.getCache().getTokenRefreshSkew(), clock,
                observations);
        if (properties.getCae().isEnabled()) {
            provider.withClientCapabilities();
        }
        return properties.getCache().isTokenBackgroundRefresh() ? provider.withBackgroundRefresh(REFRESHER)
                : provider;
    }

    /**
     * An on-behalf-of provider for the given credential (falling back to {@code entra.security.credential}).
     * <p>
     * The client id defaults to {@code entra.security.client-id}, not {@code AZURE_CLIENT_ID}: Entra only
     * exchanges a token for the application it was issued to, so the federated credential of a workload
     * identity has to be configured on this API's own app registration.
     */
    public EntraOnBehalfOfTokenProvider createOnBehalfOf(Credential credential) {
        Credential effective = effective(credential);
        String clientId = firstText(effective.getClientId(), properties.getClientId());
        OnBehalfOfTokenProvider provider = new OnBehalfOfTokenProvider(tokenEndpoint(effective), clientId,
                credential(effective), restClient, properties.getCache().getTokenRefreshSkew(),
                properties.getCache().getOnBehalfOfMaxEntries(), clock, observations);
        return properties.getCae().isEnabled() ? provider.withClientCapabilities() : provider;
    }

    private Credential effective(Credential credential) {
        Credential effective = credential.getType() == CredentialType.NONE ? properties.getCredential() : credential;
        if (effective.getType() == CredentialType.NONE) {
            throw new IllegalStateException("No Entra credential configured: set entra.security.credential.type");
        }
        return effective;
    }

    /**
     * The token endpoint for a credential. A configured or discovered {@code authority.token-endpoint} is used as is
     * for this API's tenant. Otherwise the endpoint is built from the authority host (for workload identity,
     * {@code AZURE_AUTHORITY_HOST} when the webhook sets it) and the tenant path, or the credential's own tenant
     * when that differs.
     */
    private URI tokenEndpoint(Credential effective) {
        boolean workload = effective.getType() == CredentialType.WORKLOAD_IDENTITY;
        String tenantId = firstText(effective.getTenantId(), workload ? env("AZURE_TENANT_ID") : null,
                properties.getTenantId());
        boolean ownTenant = tenantId == null || tenantId.equalsIgnoreCase(properties.getTenantId());
        if (ownTenant && endpoints.isTokenEndpointCustomized()) {
            return endpoints.tokenEndpoint();
        }
        boolean hostConfigured = properties.getAuthority().getHost() != null;
        String authority = firstText(workload && !hostConfigured ? env("AZURE_AUTHORITY_HOST") : null,
                endpoints.authorityHost().toString());
        return ClientCredentialsTokenProvider.tokenEndpoint(URI.create(authority),
                ownTenant ? endpoints.tenantPath() : tenantId);
    }

    private EntraCredential credential(Credential credential) {
        switch (credential.getType()) {
            case CLIENT_SECRET:
                return new ClientSecretCredential(credential.getClientSecret());
            case CERTIFICATE:
                return ClientCertificateCredential.fromFile(Path.of(credential.getCertificatePath()),
                        credential.getCertificatePassword());
            case KEY_VAULT_CERTIFICATE:
                if (keyVaultCredentials == null) {
                    throw new IllegalStateException(KEY_VAULT_MISSING);
                }
                return keyVaultCredentials.create(credential.getKeyVault());
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
