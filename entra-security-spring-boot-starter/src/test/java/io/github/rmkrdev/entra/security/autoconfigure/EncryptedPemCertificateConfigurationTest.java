package io.github.rmkrdev.entra.security.autoconfigure;

import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import io.github.rmkrdev.entra.security.core.token.ClientCertificateCredential;
import io.github.rmkrdev.entra.security.core.test.TestCertificates;

class EncryptedPemCertificateConfigurationTest {

    private static final String TENANT = "11111111-1111-1111-1111-111111111111";
    private static final String CLIENT = "22222222-2222-2222-2222-222222222222";
    private static final String KEY_PASSWORD = "pem-pass";

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
                "{\"expires_in\":3600,\"access_token\":\"cert-token\"}")));
        runner = new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(EntraOutboundAutoConfiguration.class))
                .withPropertyValues("entra.security.tenant-id=" + TENANT, "entra.security.client-id=" + CLIENT,
                        "entra.security.authority-host=" + wireMock.baseUrl(),
                        "entra.security.outbound.clients.orders.scope=api://orders/.default",
                        "entra.security.credential.type=certificate");
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    @Test
    void encryptedPemCertificateSignsTheClientAssertion() throws Exception {
        Path pem = TestCertificates.encryptedPem(pkcs12, dir.resolve("client-encrypted.pem"), KEY_PASSWORD,
                "PBEWithHmacSHA256AndAES_256");
        runner.withPropertyValues("entra.security.credential.certificate-path=" + pem,
                "entra.security.credential.certificate-password=" + KEY_PASSWORD)
                .run(context -> assertThat(context.getBean(EntraOutboundClients.class).token("orders").value())
                        .isEqualTo("cert-token"));

        String body = wireMock.getAllServeEvents().get(0).getRequest().getBodyAsString();
        Map<String, String> form = Arrays.stream(body.split("&")).map(p -> p.split("=", 2))
                .collect(Collectors.toMap(p -> p[0], p -> URLDecoder.decode(p[1], StandardCharsets.UTF_8)));
        SignedJWT assertion = SignedJWT.parse(form.get("client_assertion"));
        assertThat(assertion.verify(new RSASSAVerifier((RSAPublicKey) certificate.getCertificate().getPublicKey())))
                .isTrue();
        assertThat(assertion.getJWTClaimsSet().getIssuer()).isEqualTo(CLIENT);
    }

    @Test
    void wrongPasswordFailsStartupWithoutRevealingIt() throws Exception {
        Path pem = TestCertificates.encryptedPem(pkcs12, dir.resolve("client-wrong.pem"), KEY_PASSWORD,
                "PBEWithHmacSHA256AndAES_256");
        runner.withPropertyValues("entra.security.credential.certificate-path=" + pem,
                "entra.security.credential.certificate-password=not-it")
                .run(context -> assertThat(messages(context.getStartupFailure()))
                        .contains("Unable to decrypt the PEM private key; check the certificate password")
                        .doesNotContain("not-it"));
    }

    @Test
    void missingPasswordFailsStartup() throws Exception {
        Path pem = TestCertificates.encryptedPem(pkcs12, dir.resolve("client-nopass.pem"), KEY_PASSWORD,
                "PBEWithHmacSHA256AndAES_256");
        runner.withPropertyValues("entra.security.credential.certificate-path=" + pem)
                .run(context -> assertThat(messages(context.getStartupFailure()))
                        .contains("encrypted (ENCRYPTED PRIVATE KEY) but no password is configured"));
    }

    private static String messages(Throwable failure) {
        StringBuilder message = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            message.append(t.getMessage()).append('\n');
        }
        return message.toString();
    }
}
