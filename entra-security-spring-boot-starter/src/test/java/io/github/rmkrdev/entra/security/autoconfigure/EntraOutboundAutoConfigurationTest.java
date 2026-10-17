package io.github.rmkrdev.entra.security.autoconfigure;

import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;

class EntraOutboundAutoConfigurationTest {

    private static final String API_TENANT = "11111111-1111-1111-1111-111111111111";
    private static final String WI_TENANT = "66666666-6666-6666-6666-666666666666";

    private WireMockServer wireMock;
    private ApplicationContextRunner runner;

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        wireMock.stubFor(post("/" + API_TENANT + "/oauth2/v2.0/token").willReturn(okJson(
                "{\"expires_in\":3600,\"access_token\":\"secret-token\"}")));
        wireMock.stubFor(post("/" + WI_TENANT + "/oauth2/v2.0/token").willReturn(okJson(
                "{\"expires_in\":3600,\"access_token\":\"wi-token\"}")));
        wireMock.stubFor(get("/peer").willReturn(ok("pong")));
        runner = new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(EntraOutboundAutoConfiguration.class))
                .withPropertyValues("entra.security.tenant-id=" + API_TENANT,
                        "entra.security.client-id=22222222-2222-2222-2222-222222222222",
                        "entra.security.authority-host=" + wireMock.baseUrl());
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    @Test
    void clientSecretOutboundClientAddsCachedBearerToRestClient() {
        runner.withPropertyValues("entra.security.credential.type=client-secret",
                "entra.security.credential.client-secret=top-secret",
                "entra.security.outbound.clients.orders.scope=api://orders/.default",
                "entra.security.outbound.clients.orders.base-url=" + wireMock.baseUrl())
                .run(context -> {
                    EntraOutboundClients outbound = context.getBean(EntraOutboundClients.class);
                    RestClient client = RestClient.builder().baseUrl(outbound.baseUrl("orders"))
                            .requestInterceptor(outbound.interceptor("orders")).build();
                    assertThat(client.get().uri("/peer").retrieve().body(String.class)).isEqualTo("pong");
                    assertThat(client.get().uri("/peer").retrieve().body(String.class)).isEqualTo("pong");
                    assertThat(outbound.scope("orders")).isEqualTo("api://orders/.default");
                    assertThat(outbound.names()).containsExactly("orders");
                });
        wireMock.verify(1, postRequestedFor(urlEqualTo("/" + API_TENANT + "/oauth2/v2.0/token"))
                .withRequestBody(containing("client_secret=top-secret"))
                .withRequestBody(containing("client_id=22222222-2222-2222-2222-222222222222")));
        wireMock.verify(2, getRequestedFor(urlEqualTo("/peer")).withHeader("Authorization",
                equalTo("Bearer secret-token")));
    }

    @Test
    void workloadIdentityUsesAksWebhookEnvironment(@TempDir Path dir) throws Exception {
        Path tokenFile = dir.resolve("azure-identity-token");
        Files.writeString(tokenFile, "projected-sa-token");
        runner.withPropertyValues("entra.security.outbound.clients.inventory.scope=api://inventory/.default",
                "entra.security.outbound.clients.inventory.credential.type=workload-identity",
                "AZURE_FEDERATED_TOKEN_FILE=" + tokenFile, "AZURE_CLIENT_ID=77777777-7777-7777-7777-777777777777",
                "AZURE_TENANT_ID=" + WI_TENANT)
                .run(context -> {
                    EntraOutboundClients outbound = context.getBean(EntraOutboundClients.class);
                    String body = WebClient.builder().baseUrl(wireMock.baseUrl())
                            .filter(EntraWebClientSupport.filter(outbound, "inventory")).build()
                            .get().uri("/peer").retrieve().bodyToMono(String.class).block();
                    assertThat(body).isEqualTo("pong");
                });
        wireMock.verify(postRequestedFor(urlEqualTo("/" + WI_TENANT + "/oauth2/v2.0/token"))
                .withRequestBody(containing("client_assertion=projected-sa-token"))
                .withRequestBody(containing("client_id=77777777-7777-7777-7777-777777777777")));
        wireMock.verify(getRequestedFor(urlEqualTo("/peer")).withHeader("Authorization", equalTo("Bearer wi-token")));
    }

    @Test
    void unknownClientNameHasHelpfulError() {
        runner.run(context -> assertThatThrownBy(() -> context.getBean(EntraOutboundClients.class).interceptor("x"))
                .hasMessageContaining("entra.security.outbound.clients"));
    }
}
