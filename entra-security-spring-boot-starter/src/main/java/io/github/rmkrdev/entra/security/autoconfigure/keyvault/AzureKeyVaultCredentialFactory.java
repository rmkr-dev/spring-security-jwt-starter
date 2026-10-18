package io.github.rmkrdev.entra.security.autoconfigure.keyvault;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.KeyVault;
import io.github.rmkrdev.entra.security.core.token.ClientCertificateCredential;
import io.github.rmkrdev.entra.security.core.token.EntraCredential;
import io.github.rmkrdev.entra.security.core.token.RefreshingCertificateCredential;

/**
 * Key Vault credentials backed by the Azure SDK.
 * <p>
 * The vault is read with {@code DefaultAzureCredential}, which picks up Azure Workload Identity on AKS
 * ({@code AZURE_CLIENT_ID}, {@code AZURE_TENANT_ID}, {@code AZURE_FEDERATED_TOKEN_FILE}) and managed identity
 * on other Azure hosts. {@code key-vault.identity-client-id} selects a user-assigned identity. An application
 * can supply its own {@link TokenCredential} instead as a bean named {@code entraKeyVaultTokenCredential}.
 * <p>
 * The private key is read through the secrets client when {@code azure-security-keyvault-secrets} is present,
 * otherwise through the certificates client. Each certificate is cached and reloaded every
 * {@code key-vault.refresh-interval}; credentials for the same certificate share one cache.
 */
public class AzureKeyVaultCredentialFactory implements KeyVaultCredentialFactory {

    /** Metrics label for credentials created here. */
    public static final String CREDENTIAL_TYPE = "key_vault_certificate";

    /** How a certificate is loaded: from the configuration, the vault identity and a description. */
    @FunctionalInterface
    interface LoaderFactory {
        Supplier<ClientCertificateCredential> create(KeyVault keyVault, TokenCredential credential, String source);
    }

    private final Function<String, TokenCredential> tokenCredentials;
    private final LoaderFactory loaders;
    private final boolean useSecretsClient;
    private final Clock clock;
    private final Map<CacheKey, RefreshingCertificateCredential> credentials = new ConcurrentHashMap<>();
    private final Map<String, TokenCredential> defaultCredentials = new ConcurrentHashMap<>();

    /**
     * @param tokenCredential the identity used to read the vault, or {@code null} for DefaultAzureCredential
     * @param useSecretsClient whether to read the private key with the secrets client (otherwise the
     *                         certificates client)
     */
    public AzureKeyVaultCredentialFactory(TokenCredential tokenCredential, boolean useSecretsClient) {
        this(tokenCredential, useSecretsClient ? SecretClientCertificateLoader::create
                : CertificateClientCertificateLoader::create, useSecretsClient, Clock.systemUTC());
    }

    AzureKeyVaultCredentialFactory(TokenCredential tokenCredential, LoaderFactory loaders, Clock clock) {
        this(tokenCredential, loaders, true, clock);
    }

    private AzureKeyVaultCredentialFactory(TokenCredential tokenCredential, LoaderFactory loaders,
            boolean useSecretsClient, Clock clock) {
        this.loaders = Objects.requireNonNull(loaders, "loaders");
        this.useSecretsClient = useSecretsClient;
        this.clock = Objects.requireNonNull(clock, "clock");
        this.tokenCredentials = tokenCredential != null ? clientId -> tokenCredential
                : clientId -> defaultCredentials.computeIfAbsent(clientId == null ? "" : clientId,
                        AzureKeyVaultCredentialFactory::defaultAzureCredential);
    }

    @Override
    public EntraCredential create(KeyVault keyVault) {
        CacheKey key = new CacheKey(keyVault.getVaultUrl().toString(), keyVault.getCertificateName(),
                blankToNull(keyVault.getCertificateVersion()), blankToNull(keyVault.getIdentityClientId()),
                keyVault.getRefreshInterval(), keyVault.getRetryInterval());
        return credentials.computeIfAbsent(key, k -> build(keyVault, k));
    }

    private RefreshingCertificateCredential build(KeyVault keyVault, CacheKey key) {
        String source = "Key Vault " + keyVault.getVaultUrl().getHost() + " certificate '" + key.name() + "'"
                + (key.version() == null ? "" : " version " + key.version());
        TokenCredential credential = tokenCredentials.apply(key.identityClientId());
        Supplier<ClientCertificateCredential> loader = loaders.create(keyVault, credential, source);
        return new RefreshingCertificateCredential(source, loader, key.refreshInterval(), key.retryInterval(),
                CREDENTIAL_TYPE, clock);
    }

    /** Whether private keys are read with the secrets client rather than the certificates client. */
    public boolean usesSecretsClient() {
        return useSecretsClient;
    }

    /** The identity used to read a vault, for the given identity client id (may be {@code null}). */
    TokenCredential identity(String identityClientId) {
        return tokenCredentials.apply(identityClientId);
    }

    static TokenCredential defaultAzureCredential(String clientId) {
        DefaultAzureCredentialBuilder builder = new DefaultAzureCredentialBuilder();
        if (!clientId.isEmpty()) {
            builder.managedIdentityClientId(clientId).workloadIdentityClientId(clientId);
        }
        return builder.build();
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private record CacheKey(String vaultUrl, String name, String version, String identityClientId,
            Duration refreshInterval, Duration retryInterval) {
    }
}
