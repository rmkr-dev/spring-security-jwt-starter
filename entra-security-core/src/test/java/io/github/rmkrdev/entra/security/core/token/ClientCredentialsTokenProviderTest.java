package io.github.rmkrdev.entra.security.core.token;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.notContaining;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.web.client.RestClient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import io.github.rmkrdev.entra.security.core.test.TestCertificates;

class ClientCredentialsTokenProviderTest {

    private static final String TENANT = "11111111-1111-1111-1111-111111111111";
    private static final String TOKEN_PATH = "/" + TENANT + "/oauth2/v2.0/token";

    private WireMockServer wireMock;
    private URI tokenEndpoint;

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        tokenEndpoint = ClientCredentialsTokenProvider.tokenEndpoint(URI.create(wireMock.baseUrl() + "/"), TENANT);
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    @Test
    void clientSecretTokenIsRequestedOnceAndCached() {
        stubToken("token-1", 3600);
        ClientCredentialsTokenProvider provider = provider(new ClientSecretCredential("s3cret"));

        assertThat(provider.getToken("api://peer/.default").value()).isEqualTo("token-1");
        assertThat(provider.getToken("api://peer/.default").value()).isEqualTo("token-1");

        wireMock.verify(1, postRequestedFor(urlEqualTo(TOKEN_PATH))
                .withRequestBody(containing("grant_type=client_credentials"))
                .withRequestBody(containing("client_id=app-id"))
                .withRequestBody(containing("client_secret=s3cret"))
                .withRequestBody(containing("scope=api%3A%2F%2Fpeer%2F.default")));
        assertThat(tokenEndpoint.getPath()).isEqualTo(TOKEN_PATH);
    }

    @Test
    void shortLivedTokensAreRefreshedHalfwayInsteadOfEveryCall() {
        stubToken("short", 2);
        ClientCredentialsTokenProvider provider = provider(new ClientSecretCredential("s"));
        provider.getToken("a");
        provider.getToken("a");
        wireMock.verify(1, postRequestedFor(urlEqualTo(TOKEN_PATH)));
    }

    @Test
    void entraErrorsAreReportedWithoutSecrets() {
        wireMock.stubFor(post(TOKEN_PATH).willReturn(aResponse().withStatus(401)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"error\":\"invalid_client\",\"error_description\":\"AADSTS7000215: Invalid client "
                        + "secret provided.\\r\\nTrace ID: x\"}")));
        ClientCredentialsTokenProvider provider = provider(new ClientSecretCredential("s3cret"));
        assertThatThrownBy(() -> provider.getToken("api://peer/.default"))
                .isInstanceOf(EntraTokenAcquisitionException.class)
                .hasMessageContaining("HTTP 401")
                .hasMessageContaining("invalid_client")
                .hasMessageContaining("AADSTS7000215")
                .hasMessageNotContaining("s3cret")
                .satisfies(ex -> assertThat(((EntraTokenAcquisitionException) ex).getError())
                        .isEqualTo("invalid_client"));
    }

    @Test
    void workloadIdentitySendsProjectedTokenAsAssertion(@TempDir Path dir) throws Exception {
        stubToken("wi-token", 3600);
        Path file = dir.resolve("azure-identity-token");
        Files.writeString(file, "federated-sa-jwt\n");
        ClientCredentialsTokenProvider provider = provider(new WorkloadIdentityCredential(file));

        assertThat(provider.getToken("api://peer/.default").value()).isEqualTo("wi-token");
        wireMock.verify(postRequestedFor(urlEqualTo(TOKEN_PATH))
                .withRequestBody(containing("client_assertion=federated-sa-jwt"))
                .withRequestBody(containing("client_assertion_type="
                        + "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"))
                .withRequestBody(notContaining("client_secret")));
    }

    @Test
    @SuppressWarnings("deprecation")
    void certificateSendsSignedAssertion(@TempDir Path dir) throws Exception {
        stubToken("cert-token", 3600);
        Path p12 = TestCertificates.pkcs12(dir);
        ClientCertificateCredential credential = ClientCertificateCredential.fromFile(p12, TestCertificates.PASSWORD);
        ClientCredentialsTokenProvider provider = provider(credential);

        assertThat(provider.getToken("api://peer/.default").value()).isEqualTo("cert-token");

        String body = wireMock.getAllServeEvents().get(0).getRequest().getBodyAsString();
        Map<String, String> form = Arrays.stream(body.split("&")).map(p -> p.split("=", 2))
                .collect(Collectors.toMap(p -> p[0], p -> URLDecoder.decode(p[1], StandardCharsets.UTF_8)));
        SignedJWT assertion = SignedJWT.parse(form.get("client_assertion"));
        assertThat(assertion.verify(new RSASSAVerifier(
                (java.security.interfaces.RSAPublicKey) credential.getCertificate().getPublicKey()))).isTrue();
        assertThat(assertion.getHeader().getX509CertThumbprint()).isNotNull();
        assertThat(assertion.getJWTClaimsSet().getAudience()).containsExactly(tokenEndpoint.toString());
        assertThat(assertion.getJWTClaimsSet().getIssuer()).isEqualTo("app-id");
        assertThat(assertion.getJWTClaimsSet().getSubject()).isEqualTo("app-id");
    }

    @Test
    void certificateFromPem(@TempDir Path dir) throws Exception {
        Path pem = TestCertificates.pem(TestCertificates.pkcs12(dir), dir.resolve("client.pem"));
        ClientCertificateCredential credential = ClientCertificateCredential.fromFile(pem, null);
        assertThat(credential.toString()).contains("CN=entra-security-test");
        assertThatThrownBy(() -> ClientCertificateCredential.fromPem(
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"))
                .hasMessageContaining("openssl pkcs8");
    }

    private void stubToken(String token, int expiresIn) {
        wireMock.stubFor(post(TOKEN_PATH).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\"token_type\":\"Bearer\",\"expires_in\":" + expiresIn + ",\"access_token\":\""
                        + token + "\"}")));
    }

    private ClientCredentialsTokenProvider provider(EntraCredential credential) {
        return new ClientCredentialsTokenProvider(tokenEndpoint, "app-id", credential, RestClient.create(),
                Duration.ofMinutes(5), Clock.systemUTC());
    }
}
