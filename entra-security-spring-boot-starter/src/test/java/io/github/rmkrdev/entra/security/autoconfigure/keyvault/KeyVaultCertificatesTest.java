package io.github.rmkrdev.entra.security.autoconfigure.keyvault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.rmkrdev.entra.security.core.test.TestCertificates;

class KeyVaultCertificatesTest {

    private static final String SOURCE = "Key Vault kv.vault.azure.net certificate 'api'";

    @TempDir
    static Path dir;

    private static Path pkcs12;
    private static X509Certificate certificate;

    @BeforeAll
    static void keystore() throws Exception {
        pkcs12 = TestCertificates.pkcs12(dir);
        certificate = KeyVaultTestCertificates.certificate(pkcs12);
    }

    @Test
    void pkcs12SecretWithoutPassword() throws Exception {
        String value = KeyVaultTestCertificates.pkcs12Secret(pkcs12);

        assertThat(KeyVaultCertificates.fromSecret(value, "application/x-pkcs12", SOURCE).getCertificate())
                .isEqualTo(certificate);
    }

    @Test
    void pemSecretWithKeyBeforeCertificate() throws Exception {
        String value = KeyVaultTestCertificates.pemSecret(pkcs12);

        assertThat(KeyVaultCertificates.fromSecret(value, "application/x-pem-file", SOURCE).getCertificate())
                .isEqualTo(certificate);
    }

    @Test
    void missingContentTypeIsDetectedFromTheValue() throws Exception {
        assertThat(KeyVaultCertificates.fromSecret(KeyVaultTestCertificates.pemSecret(pkcs12), null, SOURCE)
                .getCertificate()).isEqualTo(certificate);
        assertThat(KeyVaultCertificates.fromSecret(KeyVaultTestCertificates.pkcs12Secret(pkcs12), "", SOURCE)
                .getCertificate()).isEqualTo(certificate);
    }

    @Test
    void unexpectedContentTypeIsRejected() {
        assertThatThrownBy(() -> KeyVaultCertificates.fromSecret("abc", "text/plain", SOURCE))
                .hasMessage(SOURCE + " has content type 'text/plain'; expected application/x-pkcs12 or "
                        + "application/x-pem-file");
    }

    @Test
    void emptyOrInvalidValuesAreRejected() {
        assertThatThrownBy(() -> KeyVaultCertificates.fromSecret(" ", null, SOURCE))
                .hasMessageContaining("has no secret value");
        assertThatThrownBy(() -> KeyVaultCertificates.fromSecret("not base64!", "application/x-pkcs12", SOURCE))
                .hasMessageContaining("is not a base64-encoded PKCS#12 certificate");
    }
}
