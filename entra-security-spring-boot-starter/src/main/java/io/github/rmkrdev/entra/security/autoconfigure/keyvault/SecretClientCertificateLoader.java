package io.github.rmkrdev.entra.security.autoconfigure.keyvault;

import java.util.function.Supplier;

import com.azure.core.credential.TokenCredential;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.KeyVault;
import io.github.rmkrdev.entra.security.core.token.ClientCertificateCredential;

/**
 * Loads a Key Vault certificate with its private key through the secrets API
 * ({@code azure-security-keyvault-secrets}). The identity needs {@code get} on secrets, for example the
 * "Key Vault Secrets User" role.
 */
final class SecretClientCertificateLoader implements Supplier<ClientCertificateCredential> {

    private final SecretClient client;
    private final String name;
    private final String version;
    private final String source;

    SecretClientCertificateLoader(SecretClient client, String name, String version, String source) {
        this.client = client;
        this.name = name;
        this.version = version;
        this.source = source;
    }

    static Supplier<ClientCertificateCredential> create(KeyVault keyVault, TokenCredential credential,
            String source) {
        SecretClient client = new SecretClientBuilder().vaultUrl(keyVault.getVaultUrl().toString())
                .credential(credential).buildClient();
        return new SecretClientCertificateLoader(client, keyVault.getCertificateName(),
                keyVault.getCertificateVersion(), source);
    }

    @Override
    public ClientCertificateCredential get() {
        KeyVaultSecret secret = version == null || version.isBlank() ? client.getSecret(name)
                : client.getSecret(name, version);
        String contentType = secret.getProperties() == null ? null : secret.getProperties().getContentType();
        return KeyVaultCertificates.fromSecret(secret.getValue(), contentType, source);
    }
}
