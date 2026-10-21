package io.github.rmkrdev.entra.security.autoconfigure.keyvault;

import java.net.URI;
import java.util.function.Supplier;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpPipeline;
import com.azure.core.http.HttpPipelineBuilder;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.core.http.policy.BearerTokenAuthenticationPolicy;
import com.azure.core.http.policy.RetryPolicy;
import com.azure.core.util.Context;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.KeyVault;
import io.github.rmkrdev.entra.security.core.token.ClientCertificateCredential;

/**
 * Loads a Key Vault certificate when only {@code azure-security-keyvault-certificates} is on the classpath.
 * <p>
 * The certificates API returns the public certificate and the id of the secret that holds the private key;
 * that secret is then read with a plain authenticated GET on the same pipeline. The identity needs
 * {@code get} on certificates and secrets, for example the "Key Vault Certificate User" role.
 */
final class CertificateClientCertificateLoader implements Supplier<ClientCertificateCredential> {

    static final String SECRETS_API_VERSION = "7.5";

    private static final ObjectMapper JSON = new ObjectMapper();

    private final CertificateClient client;
    private final HttpPipeline pipeline;
    private final String name;
    private final String version;
    private final String source;

    CertificateClientCertificateLoader(CertificateClient client, HttpPipeline pipeline, String name, String version,
            String source) {
        this.client = client;
        this.pipeline = pipeline;
        this.name = name;
        this.version = version;
        this.source = source;
    }

    static Supplier<ClientCertificateCredential> create(KeyVault keyVault, TokenCredential credential,
            String source) {
        HttpPipeline pipeline = new HttpPipelineBuilder()
                .policies(new RetryPolicy(),
                        new BearerTokenAuthenticationPolicy(credential, scope(keyVault.getVaultUrl())))
                .build();
        CertificateClient client = new CertificateClientBuilder().vaultUrl(keyVault.getVaultUrl().toString())
                .pipeline(pipeline).buildClient();
        return new CertificateClientCertificateLoader(client, pipeline, keyVault.getCertificateName(),
                keyVault.getCertificateVersion(), source);
    }

    /** The token scope for a vault: https://vault.azure.net/.default for https://name.vault.azure.net. */
    static String scope(URI vaultUrl) {
        String host = vaultUrl.getHost();
        int dot = host.indexOf('.');
        return "https://" + (dot > 0 ? host.substring(dot + 1) : host) + "/.default";
    }

    @Override
    public ClientCertificateCredential get() {
        KeyVaultCertificate certificate = version == null || version.isBlank() ? client.getCertificate(name)
                : client.getCertificateVersion(name, version);
        String secretId = certificate.getSecretId();
        if (secretId == null || secretId.isBlank()) {
            throw new IllegalStateException(source + " has no secret id; check that the certificate has been issued");
        }
        HttpRequest request = new HttpRequest(HttpMethod.GET, secretId + "?api-version=" + SECRETS_API_VERSION);
        try (HttpResponse response = pipeline.sendSync(request, Context.NONE)) {
            int status = response.getStatusCode();
            if (status != 200) {
                String hint = status == 401 || status == 403
                        ? "; the identity needs get permission on secrets (for example the 'Key Vault Certificate "
                                + "User' role)"
                        : "";
                throw new IllegalStateException("Key Vault returned HTTP " + status + " for the secret of " + source
                        + hint);
            }
            JsonNode body = JSON.readTree(response.getBodyAsBinaryData().toBytes());
            return KeyVaultCertificates.fromSecret(body.path("value").asString(null),
                    body.path("contentType").asString(null), source);
        }
        catch (JacksonException ex) {
            throw new IllegalStateException("Unable to read the secret of " + source, ex);
        }
    }
}
