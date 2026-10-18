package io.github.rmkrdev.entra.security.autoconfigure.keyvault;

import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredential;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import io.github.rmkrdev.entra.security.autoconfigure.EntraOutboundAutoConfiguration;
import io.github.rmkrdev.entra.security.autoconfigure.EntraOutboundClients;
import io.github.rmkrdev.entra.security.core.token.ClientCertificateCredential;
import io.github.rmkrdev.entra.security.core.test.TestCertificates;

class EntraKeyVaultAutoConfigurationTest {

    private static final String TENANT = "11111111-1111-1111-1111-111111111111";
    private static final String CLIENT = "22222222-2222-2222-2222-222222222222";
    private static final String KEY_VAULT = "entra.security.credential.type=key-vault-certificate";
    private static final String VAULT_URL =
            "entra.security.credential.key-vault.vault-url=https://kv-test.vault.azure.net";
    private static final String CERTIFICATE = "entra.security.credential.key-vault.certificate-name=api-client";
    private static final String OUTBOUND = "entra.security.outbound.clients.orders.scope=api://orders/.default";

    @TempDir
    static Path dir;

    private static Path pkcs12;
    private static ClientCertificateCredential certificate;

    private WireMockServer wireMock;
    private ApplicationContextRunner runner;

    @BeforeAll
    static void keystore() throws Exception {
        pkcs12 = TestCertificates.pkcs12(dir);
        certificate = ClientCertificateCredential.fromFile(pkcs12, TestCertificates.PASSWORD);
    }

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        wireMock.stubFor(post("/" + TENANT + "/oauth2/v2.0/token").willReturn(okJson(
                "{\"expires_in\":3600,\"access_token\":\"kv-token\"}")));
        runner = new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(EntraKeyVaultAutoConfiguration.class,
                        EntraOutboundAutoConfiguration.class))
                .withPropertyValues("entra.security.tenant-id=" + TENANT, "entra.security.client-id=" + CLIENT,
                        "entra.security.authority-host=" + wireMock.baseUrl());
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    @Test
    void azureSdkOnTheClasspathRegistersTheFactoryWithTheSecretsClient() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(KeyVaultCredentialFactory.class);
            AzureKeyVaultCredentialFactory factory = context.getBean(AzureKeyVaultCredentialFactory.class);
            assertThat(factory.usesSecretsClient()).isTrue();
            assertThat(factory.identity(null)).isInstanceOf(DefaultAzureCredential.class);
        });
    }

    @Test
    void certificatesLibraryAloneIsEnough() {
        runner.withClassLoader(new FilteredClassLoader("com.azure.security.keyvault.secrets"))
                .run(context -> assertThat(
                        context.getBean(AzureKeyVaultCredentialFactory.class).usesSecretsClient()).isFalse());
    }

    @Test
    void notRegisteredWithoutAKeyVaultClientLibrary() {
        runner.withClassLoader(new FilteredClassLoader("com.azure.security.keyvault.secrets",
                "com.azure.security.keyvault.certificates"))
                .run(context -> assertThat(context).doesNotHaveBean(KeyVaultCredentialFactory.class));
    }

    @Test
    void notRegisteredWithoutAzureIdentity() {
        runner.withClassLoader(new FilteredClassLoader("com.azure.identity"))
                .run(context -> assertThat(context).doesNotHaveBean(KeyVaultCredentialFactory.class));
    }

    @Test
    void keyVaultCredentialWithoutTheAzureSdkFailsWithTheDependenciesToAdd() {
        runner.withClassLoader(new FilteredClassLoader("com.azure.security.keyvault.secrets",
                "com.azure.security.keyvault.certificates"))
                .withPropertyValues(KEY_VAULT, VAULT_URL, CERTIFICATE)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(messages(context.getStartupFailure())).contains(
                            "credential.type=key-vault-certificate needs the Azure SDK on the classpath: add "
                                    + "com.azure:azure-identity and com.azure:azure-security-keyvault-secrets");
                });
    }

    @Test
    void applicationTokenCredentialBeanReplacesDefaultAzureCredential() {
        TokenCredential application = mock(TokenCredential.class);
        runner.withBean(EntraKeyVaultAutoConfiguration.TOKEN_CREDENTIAL_BEAN, TokenCredential.class,
                () -> application)
                .run(context -> assertThat(context.getBean(AzureKeyVaultCredentialFactory.class).identity(null))
                        .isSameAs(application));
    }

    @Test
    void keyVaultSettingsAreValidated() {
        runner.withPropertyValues(KEY_VAULT, CERTIFICATE).run(context -> assertThat(messages(
                context.getStartupFailure())).contains("credential.key-vault.vault-url and "
                        + "credential.key-vault.certificate-name are required"));
        runner.withPropertyValues(KEY_VAULT, CERTIFICATE,
                "entra.security.credential.key-vault.vault-url=http://kv-test.vault.azure.net")
                .run(context -> assertThat(messages(context.getStartupFailure()))
                        .contains("credential.key-vault.vault-url must be an https URL"));
    }

    @Test
    void outboundClientSignsWithTheKeyVaultCertificate() throws Exception {
        AtomicInteger loads = new AtomicInteger();
        runner.withUserConfiguration(TestVault.class)
                .withBean("testLoads", AtomicInteger.class, () -> loads)
                .withPropertyValues(KEY_VAULT, VAULT_URL, CERTIFICATE, OUTBOUND)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    EntraOutboundClients outbound = context.getBean(EntraOutboundClients.class);
                    assertThat(outbound.token("orders").value()).isEqualTo("kv-token");
                    assertThat(outbound.token("orders").value()).isEqualTo("kv-token");
                });
        assertThat(loads).hasValue(1);
        SignedJWT assertion = assertion();
        assertThat(verify(assertion)).isTrue();
        assertThat(assertion.getJWTClaimsSet().getIssuer()).isEqualTo(CLIENT);
    }

    @Test
    void outboundClientCanUseItsOwnKeyVaultCertificate() throws Exception {
        AtomicInteger loads = new AtomicInteger();
        runner.withUserConfiguration(TestVault.class)
                .withBean("testLoads", AtomicInteger.class, () -> loads)
                .withPropertyValues(OUTBOUND,
                        "entra.security.outbound.clients.orders.credential.type=key-vault-certificate",
                        "entra.security.outbound.clients.orders.credential.key-vault.vault-url="
                                + "https://kv.vault.azure.net",
                        "entra.security.outbound.clients.orders.credential.key-vault.certificate-name=orders")
                .run(context -> assertThat(context.getBean(EntraOutboundClients.class).token("orders").value())
                        .isEqualTo("kv-token"));
        assertThat(verify(assertion())).isTrue();
    }

    private SignedJWT assertion() throws Exception {
        String body = wireMock.getAllServeEvents().get(0).getRequest().getBodyAsString();
        Map<String, String> form = Arrays.stream(body.split("&")).map(p -> p.split("=", 2))
                .collect(Collectors.toMap(p -> p[0], p -> URLDecoder.decode(p[1], StandardCharsets.UTF_8)));
        assertThat(form).containsEntry("client_id", CLIENT).doesNotContainKey("client_secret");
        return SignedJWT.parse(form.get("client_assertion"));
    }

    private static boolean verify(SignedJWT assertion) throws Exception {
        return assertion.verify(new RSASSAVerifier((RSAPublicKey) certificate.getCertificate().getPublicKey()));
    }

    private static String messages(Throwable failure) {
        StringBuilder message = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            message.append(t.getMessage()).append('\n');
        }
        return message.toString();
    }

    /** Stands in for Key Vault: the factory is real, the vault read returns the test certificate. */
    @Configuration(proxyBeanMethods = false)
    static class TestVault {

        @Bean
        KeyVaultCredentialFactory testKeyVaultCredentialFactory(AtomicInteger testLoads) {
            return new AzureKeyVaultCredentialFactory(mock(TokenCredential.class),
                    (keyVault, credential, source) -> () -> {
                        testLoads.incrementAndGet();
                        return certificate;
                    }, Clock.systemUTC());
        }
    }
}
