package io.github.rmkrdev.entra.security.autoconfigure.it;

import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static io.github.rmkrdev.entra.security.support.EntraTestServer.TOKENS;
import static io.github.rmkrdev.entra.security.support.EntraTestServer.WIRE_MOCK;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.autoconfigure.EntraOutboundClients;
import io.github.rmkrdev.entra.security.core.test.TestCertificates;
import io.github.rmkrdev.entra.security.core.test.TestTokens;
import io.github.rmkrdev.entra.security.support.EntraTestServer;
import io.github.rmkrdev.entra.security.support.TlsTestCertificates;

/**
 * Service-to-service calls through one routed RestClient and WebClient: an external HTTPS API
 * (example.text.com, with a certificate credential), in-cluster services (*.shop.svc.cluster.local, with
 * workload identity) and this service itself through its cluster name, where the app-only token is
 * validated and mapped through app roles end to end. Host names resolve to loopback through the test
 * hosts file.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EntraServiceToServiceIntegrationTest {

    static final Path WORK;
    static final Path SERVER_KEYSTORE;
    static final WireMockServer EXTERNAL;
    static final WireMockServer CLUSTER;
    static final String SELF_SCOPE = "api://" + TestTokens.CLIENT_ID + "/.default";

    static {
        try {
            WORK = Files.createTempDirectory("s2s");
            SERVER_KEYSTORE = TlsTestCertificates.serverKeystore(WORK, "example.text.com");
            Files.writeString(WORK.resolve("federated.jwt"), "federated-assertion", StandardCharsets.US_ASCII);
            TestCertificates.pkcs12(WORK);
        }
        catch (Exception ex) {
            throw new ExceptionInInitializerError(ex);
        }
        EXTERNAL = new WireMockServer(options().httpDisabled(true).dynamicHttpsPort()
                .keystorePath(SERVER_KEYSTORE.toString()).keystoreType("PKCS12")
                .keystorePassword(TlsTestCertificates.PASSWORD).keyManagerPassword(TlsTestCertificates.PASSWORD));
        EXTERNAL.start();
        CLUSTER = new WireMockServer(options().dynamicPort());
        CLUSTER.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            EXTERNAL.stop();
            CLUSTER.stop();
        }));
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        EntraTestServer.register(registry);
        String clients = "entra.security.outbound.clients.";
        registry.add(clients + "external-api.scope", () -> "api://external-api/.default");
        registry.add(clients + "external-api.credential.type", () -> "certificate");
        registry.add(clients + "external-api.credential.certificate-path", () -> WORK.resolve("client.p12").toString());
        registry.add(clients + "external-api.credential.certificate-password", () -> TestCertificates.PASSWORD);
        registry.add(clients + "self.scope", () -> SELF_SCOPE);
        registry.add(clients + "inventory.scope", () -> "api://inventory/.default");
        registry.add(clients + "inventory.credential.type", () -> "workload-identity");
        registry.add(clients + "inventory.credential.federated-token-file",
                () -> WORK.resolve("federated.jwt").toString());
        String routes = "entra.security.outbound.routes";
        registry.add(routes + "[0].urls[0]", () -> "https://example.text.com/api/**");
        registry.add(routes + "[0].client", () -> "external-api");
        registry.add(routes + "[1].hosts[0]", () -> "orders.shop.svc.cluster.local");
        registry.add(routes + "[1].client", () -> "self");
        registry.add(routes + "[2].name", () -> "shop");
        registry.add(routes + "[2].hosts[0]", () -> "*.shop.svc.cluster.local");
        registry.add(routes + "[2].paths[0]", () -> "/stock/**");
        registry.add(routes + "[2].client", () -> "inventory");
        registry.add(routes + "[2].scope", () -> "api://inventory/Stock.Read");
        registry.add("entra.security.outbound.skip-hosts[0]", () -> "public.shop.svc.cluster.local");
    }

    @LocalServerPort
    int port;

    @Autowired
    ObjectProvider<RestClient.Builder> restClientBuilder;

    @Autowired
    ObjectProvider<WebClient.Builder> webClientBuilder;

    @Autowired
    EntraOutboundClients outbound;

    SSLContext ssl;

    @BeforeEach
    void stubs() throws Exception {
        ssl = TlsTestCertificates.trusting(SERVER_KEYSTORE);
        EXTERNAL.resetAll();
        CLUSTER.resetAll();
        EXTERNAL.stubFor(any(anyUrl()).willReturn(ok("external")));
        CLUSTER.stubFor(any(anyUrl()).willReturn(ok("cluster")));
        String tokenPath = "/" + TestTokens.TENANT_ID + "/oauth2/v2.0/token";
        WIRE_MOCK.stubFor(post(urlPathEqualTo(tokenPath)).atPriority(1)
                .withRequestBody(containing("external-api"))
                .willReturn(okJson(token("external-token"))));
        WIRE_MOCK.stubFor(post(urlPathEqualTo(tokenPath)).atPriority(1)
                .withRequestBody(containing("Stock.Read"))
                .willReturn(okJson(token("inventory-token"))));
        WIRE_MOCK.stubFor(post(urlPathEqualTo(tokenPath)).atPriority(1)
                .withRequestBody(containing(TestTokens.CLIENT_ID + "%2F.default"))
                .willReturn(okJson(token(TOKENS.service().roles("Orders.Sync").build()))));
    }

    static String token(String value) {
        return "{\"token_type\":\"Bearer\",\"expires_in\":3600,\"access_token\":\"" + value + "\"}";
    }

    RestClient restClient() {
        HttpClient http = HttpClient.newBuilder().sslContext(ssl).connectTimeout(Duration.ofSeconds(2)).build();
        return restClientBuilder.getObject().requestFactory(new JdkClientHttpRequestFactory(http)).build();
    }

    WebClient webClient() {
        HttpClient http = HttpClient.newBuilder().sslContext(ssl).connectTimeout(Duration.ofSeconds(2)).build();
        return webClientBuilder.getObject().clientConnector(new JdkClientHttpConnector(http)).build();
    }

    @Test
    void oneRestClientSendsTheRightTokenToEachHost() {
        RestClient client = restClient();
        String external = "https://example.text.com:" + EXTERNAL.httpsPort();
        String cluster = ":" + CLUSTER.port();

        assertThat(client.get().uri(external + "/api/a").retrieve().body(String.class)).isEqualTo("external");
        assertThat(client.get().uri("http://inventory.shop.svc.cluster.local" + cluster + "/stock/1")
                .retrieve().body(String.class)).isEqualTo("cluster");
        client.get().uri("http://inventory.shop.svc.cluster.local" + cluster + "/health").retrieve()
                .toBodilessEntity();
        client.get().uri("http://public.shop.svc.cluster.local" + cluster + "/stock/2").retrieve().toBodilessEntity();
        client.get().uri(external + "/other").retrieve().toBodilessEntity();

        EXTERNAL.verify(getRequestedFor(urlEqualTo("/api/a"))
                .withHeader("Authorization", equalTo("Bearer external-token")));
        EXTERNAL.verify(getRequestedFor(urlEqualTo("/other")).withHeader("Authorization", absent()));
        CLUSTER.verify(getRequestedFor(urlEqualTo("/stock/1"))
                .withHeader("Host", containing("inventory.shop.svc.cluster.local"))
                .withHeader("Authorization", equalTo("Bearer inventory-token")));
        CLUSTER.verify(getRequestedFor(urlEqualTo("/health")).withHeader("Authorization", absent()));
        CLUSTER.verify(getRequestedFor(urlEqualTo("/stock/2"))
                .withHeader("Host", containing("public.shop.svc.cluster.local"))
                .withHeader("Authorization", absent()));

        String tokenPath = "/" + TestTokens.TENANT_ID + "/oauth2/v2.0/token";
        WIRE_MOCK.verify(postRequestedFor(urlPathEqualTo(tokenPath))
                .withRequestBody(containing("external-api"))
                .withRequestBody(containing("client_assertion_type")));
        WIRE_MOCK.verify(postRequestedFor(urlPathEqualTo(tokenPath))
                .withRequestBody(containing("Stock.Read"))
                .withRequestBody(containing("client_assertion=federated-assertion")));
    }

    @Test
    void routedServiceTokenIsAcceptedByThePeerAndMappedThroughAppRoles() {
        RestClient client = restClient();
        String self = "http://orders.shop.svc.cluster.local:" + port;

        assertThat(client.get().uri(self + "/internal/sync").retrieve().body(String.class)).isEqualTo("synced");
        assertThat(client.get().uri(self + "/internal/reports").retrieve().body(String.class)).isEqualTo("reports");
        assertThatThrownBy(() -> client.get().uri(self + "/admin").retrieve().toBodilessEntity())
                .isInstanceOfSatisfying(HttpClientErrorException.class,
                        ex -> assertThat(ex.getStatusCode().value()).isEqualTo(403));
        assertThatThrownBy(() -> client.get().uri(self + "/internal/sync")
                .header("Authorization", "Bearer " + TOKENS.service().build()).retrieve().toBodilessEntity())
                .isInstanceOfSatisfying(HttpClientErrorException.class,
                        ex -> assertThat(ex.getStatusCode().value()).isEqualTo(403));
        assertThatThrownBy(() -> RestClient.builder().requestFactory(new JdkClientHttpRequestFactory()).build().get().uri(self + "/internal/sync").retrieve()
                .toBodilessEntity())
                .isInstanceOfSatisfying(HttpClientErrorException.class,
                        ex -> assertThat(ex.getStatusCode().value()).isEqualTo(401));
    }

    @Test
    void oneWebClientSendsTheRightTokenToEachHost() {
        WebClient client = webClient();
        String external = "https://example.text.com:" + EXTERNAL.httpsPort();

        assertThat(client.get().uri(external + "/api/b").retrieve().bodyToMono(String.class).block())
                .isEqualTo("external");
        client.get().uri("http://public.shop.svc.cluster.local:" + CLUSTER.port() + "/stock/3").retrieve()
                .toBodilessEntity().block();
        assertThat(client.get().uri("http://orders.shop.svc.cluster.local:" + port + "/internal/sync").retrieve()
                .bodyToMono(String.class).block()).isEqualTo("synced");

        EXTERNAL.verify(getRequestedFor(urlEqualTo("/api/b"))
                .withHeader("Authorization", equalTo("Bearer external-token")));
        CLUSTER.verify(getRequestedFor(urlEqualTo("/stock/3")).withHeader("Authorization", absent()));
    }

    @Test
    void routesAreExposedInOrder() {
        assertThat(outbound.routes()).extracting(EntraOutboundClients.Route::name)
                .containsExactly("external-api", "self", "shop");
        assertThat(outbound.hasRoutes()).isTrue();
    }
}
