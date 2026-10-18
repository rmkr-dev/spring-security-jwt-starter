package io.github.rmkrdev.entra.security.autoconfigure.keyvault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredential;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.KeyVault;
import io.github.rmkrdev.entra.security.core.token.ClientCertificateCredential;
import io.github.rmkrdev.entra.security.core.token.EntraCredential;
import io.github.rmkrdev.entra.security.core.token.RefreshingCertificateCredential;
import io.github.rmkrdev.entra.security.core.test.TestCertificates;

class AzureKeyVaultCredentialFactoryTest {

    @TempDir
    static Path dir;

    private static ClientCertificateCredential certificate;

    private final List<String> sources = new ArrayList<>();
    private final List<TokenCredential> identities = new ArrayList<>();

    @BeforeAll
    static void keystore() throws Exception {
        certificate = ClientCertificateCredential.fromFile(TestCertificates.pkcs12(dir), TestCertificates.PASSWORD);
    }

    @Test
    void sameCertificateSharesOneRefreshingCredential() {
        AzureKeyVaultCredentialFactory factory = factory(mock(TokenCredential.class));

        EntraCredential first = factory.create(keyVault("api", null));
        EntraCredential second = factory.create(keyVault("api", ""));
        EntraCredential other = factory.create(keyVault("other", null));

        assertThat(first).isSameAs(second).isInstanceOf(RefreshingCertificateCredential.class);
        assertThat(other).isNotSameAs(first);
        assertThat(first.credentialType()).isEqualTo("key_vault_certificate");
        assertThat(sources).containsExactly("Key Vault kv-test.vault.azure.net certificate 'api'",
                "Key Vault kv-test.vault.azure.net certificate 'other'");
    }

    @Test
    void certificateIsLoadedOnFirstUseNotWhenCreated() {
        List<String> loads = new ArrayList<>();
        AzureKeyVaultCredentialFactory factory = new AzureKeyVaultCredentialFactory(mock(TokenCredential.class),
                (keyVault, credential, source) -> () -> {
                    loads.add(source);
                    return certificate;
                }, Clock.systemUTC());

        RefreshingCertificateCredential credential = (RefreshingCertificateCredential) factory
                .create(keyVault("api", "v3"));

        assertThat(loads).isEmpty();
        assertThat(credential.getCertificate()).isEqualTo(certificate.getCertificate());
        assertThat(loads).containsExactly("Key Vault kv-test.vault.azure.net certificate 'api' version v3");
    }

    @Test
    void applicationTokenCredentialIsUsedForEveryVault() {
        TokenCredential application = mock(TokenCredential.class);
        AzureKeyVaultCredentialFactory factory = factory(application);

        factory.create(keyVault("api", null));
        KeyVault withClientId = keyVault("other", null);
        withClientId.setIdentityClientId("44444444-4444-4444-4444-444444444444");
        factory.create(withClientId);

        assertThat(identities).containsExactly(application, application);
    }

    @Test
    void defaultAzureCredentialIsBuiltPerIdentityClientId() {
        AzureKeyVaultCredentialFactory factory = factory(null);

        factory.create(keyVault("a", null));
        factory.create(keyVault("b", null));
        KeyVault userAssigned = keyVault("c", null);
        userAssigned.setIdentityClientId("44444444-4444-4444-4444-444444444444");
        factory.create(userAssigned);

        assertThat(identities).hasSize(3).allMatch(DefaultAzureCredential.class::isInstance);
        assertThat(identities.get(0)).isSameAs(identities.get(1));
        assertThat(identities.get(2)).isNotSameAs(identities.get(0));
    }

    @Test
    void publicConstructorPicksTheClientLibrary() {
        assertThat(new AzureKeyVaultCredentialFactory(mock(TokenCredential.class), true)
                .create(keyVault("api", null))).isInstanceOf(RefreshingCertificateCredential.class);
        assertThat(new AzureKeyVaultCredentialFactory(mock(TokenCredential.class), false)
                .create(keyVault("api", null))).isInstanceOf(RefreshingCertificateCredential.class);
    }

    private AzureKeyVaultCredentialFactory factory(TokenCredential tokenCredential) {
        return new AzureKeyVaultCredentialFactory(tokenCredential, (keyVault, credential, source) -> {
            sources.add(source);
            identities.add(credential);
            return () -> certificate;
        }, Clock.systemUTC());
    }

    static KeyVault keyVault(String name, String version) {
        KeyVault keyVault = new KeyVault();
        keyVault.setVaultUrl(URI.create("https://kv-test.vault.azure.net"));
        keyVault.setCertificateName(name);
        keyVault.setCertificateVersion(version);
        keyVault.setRefreshInterval(Duration.ofMinutes(30));
        return keyVault;
    }
}
