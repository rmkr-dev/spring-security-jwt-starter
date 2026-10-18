package io.github.rmkrdev.entra.security.core.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import io.github.rmkrdev.entra.security.core.test.TestCertificates;

class EncryptedPemCredentialTest {

    private static final String KEY_PASSWORD = "pem-key-password";

    @TempDir
    static Path dir;

    private static Path pkcs12;

    @BeforeAll
    static void keystore() throws Exception {
        pkcs12 = TestCertificates.pkcs12(dir);
    }

    @ParameterizedTest
    @ValueSource(strings = { "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA512AndAES_128", "PBEWithSHA1AndDESede" })
    void encryptedPkcs8KeyIsDecryptedWithThePassword(String algorithm) throws Exception {
        Path pem = TestCertificates.encryptedPem(pkcs12, dir.resolve(algorithm + ".pem"), KEY_PASSWORD, algorithm);
        assertThat(Files.readString(pem)).contains("-----BEGIN ENCRYPTED PRIVATE KEY-----");

        ClientCertificateCredential credential = ClientCertificateCredential.fromFile(pem, KEY_PASSWORD);

        URI endpoint = URI.create("https://login.example/tenant/oauth2/v2.0/token");
        SignedJWT assertion = SignedJWT.parse(credential.createAssertion(endpoint, "app-id"));
        assertThat(assertion.verify(new RSASSAVerifier((RSAPublicKey) credential.getCertificate().getPublicKey())))
                .isTrue();
    }

    @Test
    void encryptedKeyWithoutPasswordIsRejected() throws Exception {
        String pem = encrypted("PBEWithHmacSHA256AndAES_256");

        assertThatThrownBy(() -> ClientCertificateCredential.fromPem(pem))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("encrypted (ENCRYPTED PRIVATE KEY) but no password is configured");
        assertThatThrownBy(() -> ClientCertificateCredential.fromPem(pem, ""))
                .hasMessageContaining("no password is configured");
    }

    @Test
    void wrongPasswordIsReportedWithoutLeakingIt() throws Exception {
        String pem = encrypted("PBEWithHmacSHA256AndAES_256");

        assertThatThrownBy(() -> ClientCertificateCredential.fromPem(pem, "not-the-password"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unable to decrypt the PEM private key; check the certificate password")
                .hasMessageNotContaining("not-the-password");
    }

    @Test
    void passwordIsIgnoredForAnUnencryptedKey() throws Exception {
        String pem = TestCertificates.pemText(pkcs12);

        assertThat(ClientCertificateCredential.fromPem(pem, "unused").getCertificate()).isNotNull();
    }

    @Test
    void corruptEncryptedBlockIsRejected() {
        assertThatThrownBy(() -> ClientCertificateCredential.fromPem(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----", KEY_PASSWORD))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid ENCRYPTED PRIVATE KEY block");
    }

    private static String encrypted(String algorithm) throws Exception {
        Path pem = TestCertificates.encryptedPem(pkcs12, Files.createTempFile(dir, "key", ".pem"), KEY_PASSWORD,
                algorithm);
        return Files.readString(pem, StandardCharsets.US_ASCII);
    }
}
