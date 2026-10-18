package io.github.rmkrdev.entra.security.autoconfigure.keyvault;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties;
import io.github.rmkrdev.entra.security.core.token.EntraCredential;

/**
 * Creates credentials for {@code credential.type=key-vault-certificate}.
 * <p>
 * Registered by {@link EntraKeyVaultAutoConfiguration} only when the Azure SDK is on the classpath, so this
 * interface itself does not depend on it.
 */
@FunctionalInterface
public interface KeyVaultCredentialFactory {

    /**
     * A credential that signs client assertions with the given Key Vault certificate. Implementations may
     * return the same instance for the same certificate, so it is loaded and refreshed only once.
     */
    EntraCredential create(EntraSecurityProperties.KeyVault keyVault);
}
