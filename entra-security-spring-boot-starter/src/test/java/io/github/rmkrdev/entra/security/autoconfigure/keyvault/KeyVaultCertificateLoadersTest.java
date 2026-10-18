package io.github.rmkrdev.entra.security.autoconfigure.keyvault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.nio.file.Path;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpPipeline;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.core.util.BinaryData;
import com.azure.core.util.Context;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.KeyVault;
import io.github.rmkrdev.entra.security.core.test.TestCertificates;

class KeyVaultCertificateLoadersTest {

    private static final String SOURCE = "Key Vault kv-test.vault.azure.net certificate 'api'";
    private static final String SECRET_ID = "https://kv-test.vault.azure.net/secrets/api/0f1e2d3c";

    @TempDir
    static Path dir;

    private static String pkcs12Secret;
    private static String pemSecret;
    private static X509Certificate certificate;

    @BeforeAll
    static void keystore() throws Exception {
        Path pkcs12 = TestCertificates.pkcs12(dir);
        pkcs12Secret = KeyVaultTestCertificates.pkcs12Secret(pkcs12);
        pemSecret = KeyVaultTestCertificates.pemSecret(pkcs12);
        certificate = KeyVaultTestCertificates.certificate(pkcs12);
    }

    @Test
    void secretClientReadsTheLatestVersionByDefault() {
        SecretClient client = mock(SecretClient.class);
        when(client.getSecret("api")).thenReturn(secret(pkcs12Secret, "application/x-pkcs12"));

        SecretClientCertificateLoader loader = new SecretClientCertificateLoader(client, "api", null, SOURCE);

        assertThat(loader.get().getCertificate()).isEqualTo(certificate);
        verify(client, never()).getSecret(any(), any());
    }

    @Test
    void secretClientReadsAPinnedVersion() {
        SecretClient client = mock(SecretClient.class);
        when(client.getSecret("api", "v2")).thenReturn(secret(pemSecret, "application/x-pem-file"));

        assertThat(new SecretClientCertificateLoader(client, "api", "v2", SOURCE).get().getCertificate())
                .isEqualTo(certificate);
    }

    @Test
    void secretClientErrorsPropagate() {
        SecretClient client = mock(SecretClient.class);
        when(client.getSecret("api")).thenThrow(new IllegalStateException("Status code 403, Forbidden"));

        assertThatThrownBy(() -> new SecretClientCertificateLoader(client, "api", " ", SOURCE).get())
                .hasMessageContaining("403");
    }

    @Test
    void secretClientLoaderIsBuiltFromConfiguration() {
        KeyVault keyVault = keyVault();
        assertThat(SecretClientCertificateLoader.create(keyVault, mock(TokenCredential.class), SOURCE))
                .isInstanceOf(SecretClientCertificateLoader.class);
    }

    @Test
    void certificateClientFollowsTheSecretIdOfTheLatestVersion() {
        CertificateClient client = mock(CertificateClient.class);
        KeyVaultCertificateWithPolicy latest = mock(KeyVaultCertificateWithPolicy.class);
        when(latest.getSecretId()).thenReturn(SECRET_ID);
        when(client.getCertificate("api")).thenReturn(latest);
        HttpPipeline pipeline = pipeline(200, "{\"value\":\"" + pkcs12Secret
                + "\",\"contentType\":\"application/x-pkcs12\",\"id\":\"" + SECRET_ID + "\"}");

        CertificateClientCertificateLoader loader = new CertificateClientCertificateLoader(client, pipeline, "api",
                null, SOURCE);

        assertThat(loader.get().getCertificate()).isEqualTo(certificate);
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        verify(pipeline).sendSync(request.capture(), any(Context.class));
        assertThat(request.getValue().getHttpMethod()).isEqualTo(HttpMethod.GET);
        assertThat(request.getValue().getUrl()).hasToString(SECRET_ID + "?api-version=7.5");
    }

    @Test
    void certificateClientReadsAPinnedVersion() {
        CertificateClient client = mock(CertificateClient.class);
        KeyVaultCertificate pinned = mock(KeyVaultCertificate.class);
        when(pinned.getSecretId()).thenReturn(SECRET_ID);
        when(client.getCertificateVersion("api", "v1")).thenReturn(pinned);
        String pem = pemSecret.replace("\n", "\\n");
        HttpPipeline pipeline = pipeline(200, "{\"value\":\"" + pem + "\",\"contentType\":\"application/x-pem-file\"}");

        assertThat(new CertificateClientCertificateLoader(client, pipeline, "api", "v1", SOURCE).get()
                .getCertificate()).isEqualTo(certificate);
    }

    @Test
    void certificateClientExplainsAForbiddenSecret() {
        CertificateClient client = mock(CertificateClient.class);
        KeyVaultCertificateWithPolicy latest = mock(KeyVaultCertificateWithPolicy.class);
        when(latest.getSecretId()).thenReturn(SECRET_ID);
        when(client.getCertificate("api")).thenReturn(latest);

        assertThatThrownBy(() -> new CertificateClientCertificateLoader(client, pipeline(403, "{}"), "api", null,
                SOURCE).get()).hasMessage("Key Vault returned HTTP 403 for the secret of " + SOURCE
                        + "; the identity needs get permission on secrets (for example the 'Key Vault Certificate "
                        + "User' role)");
        assertThatThrownBy(() -> new CertificateClientCertificateLoader(client, pipeline(500, "{}"), "api", null,
                SOURCE).get()).hasMessage("Key Vault returned HTTP 500 for the secret of " + SOURCE);
    }

    @Test
    void certificateWithoutSecretIdIsRejected() {
        CertificateClient client = mock(CertificateClient.class);
        when(client.getCertificate("api")).thenReturn(mock(KeyVaultCertificateWithPolicy.class));

        assertThatThrownBy(() -> new CertificateClientCertificateLoader(client, pipeline(200, "{}"), "api", null,
                SOURCE).get()).hasMessageContaining("has no secret id");
    }

    @Test
    void certificateClientLoaderIsBuiltFromConfiguration() {
        assertThat(CertificateClientCertificateLoader.create(keyVault(), mock(TokenCredential.class), SOURCE))
                .isInstanceOf(CertificateClientCertificateLoader.class);
    }

    @Test
    void vaultScopeFollowsTheVaultsCloud() {
        assertThat(CertificateClientCertificateLoader.scope(URI.create("https://kv-test.vault.azure.net")))
                .isEqualTo("https://vault.azure.net/.default");
        assertThat(CertificateClientCertificateLoader.scope(URI.create("https://kv.vault.usgovcloudapi.net/")))
                .isEqualTo("https://vault.usgovcloudapi.net/.default");
    }

    private static KeyVaultSecret secret(String value, String contentType) {
        KeyVaultSecret secret = new KeyVaultSecret("api", value);
        SecretProperties properties = new SecretProperties().setContentType(contentType);
        secret.setProperties(properties);
        return secret;
    }

    private static HttpPipeline pipeline(int status, String body) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.getStatusCode()).thenReturn(status);
        when(response.getBodyAsBinaryData()).thenReturn(BinaryData.fromString(body));
        HttpPipeline pipeline = mock(HttpPipeline.class);
        when(pipeline.sendSync(any(HttpRequest.class), any(Context.class))).thenReturn(response);
        return pipeline;
    }

    private static KeyVault keyVault() {
        KeyVault keyVault = new KeyVault();
        keyVault.setVaultUrl(URI.create("https://kv-test.vault.azure.net"));
        keyVault.setCertificateName("api");
        return keyVault;
    }
}
