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
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.OutboundFlow;
import io.github.rmkrdev.entra.security.core.web.InteractionRequiredExceptionHandler;
import io.github.rmkrdev.entra.security.core.web.server.ServerInteractionRequiredExceptionHandler;

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
    void caeIsOffByDefaultAndDeclaresCp1WhenEnabled() {
        String[] props = { "entra.security.credential.type=client-secret",
                "entra.security.credential.client-secret=top-secret",
                "entra.security.outbound.clients.orders.scope=api://orders/.default",
                "entra.security.outbound.clients.me.scope=api://me/.default",
                "entra.security.outbound.clients.me.flow=on-behalf-of" };
        runner.withPropertyValues(props).run(context -> {
            assertThat(context.getBean(EntraOutboundClients.class).isCae()).isFalse();
            assertThat(context).doesNotHaveBean(
                    io.github.rmkrdev.entra.security.core.web.ClaimsChallengeExceptionHandler.class);
        });
        runner.withPropertyValues(props).withPropertyValues("entra.security.cae.enabled=true").run(context -> {
            EntraOutboundClients outbound = context.getBean(EntraOutboundClients.class);
            assertThat(outbound.isCae()).isTrue();
            outbound.token("orders");
            assertThat(outbound.interceptor("me")).isNotNull();
            assertThat(EntraWebClientSupport.filter(outbound, "me", "api://me/x")).isNotNull();
        });
        wireMock.verify(postRequestedFor(urlEqualTo("/" + API_TENANT + "/oauth2/v2.0/token"))
                .withRequestBody(containing("xms_cc")));
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(EntraOutboundAutoConfiguration.class))
                .withPropertyValues("entra.security.tenant-id=" + API_TENANT,
                        "entra.security.client-id=22222222-2222-2222-2222-222222222222",
                        "entra.security.cae.enabled=true")
                .run(context -> assertThat(context).hasSingleBean(
                        io.github.rmkrdev.entra.security.core.web.ClaimsChallengeExceptionHandler.class));
        new ReactiveWebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(EntraOutboundAutoConfiguration.class))
                .withPropertyValues("entra.security.tenant-id=" + API_TENANT,
                        "entra.security.client-id=22222222-2222-2222-2222-222222222222",
                        "entra.security.cae.enabled=true")
                .run(context -> assertThat(context).hasSingleBean(
                        io.github.rmkrdev.entra.security.core.web.server.ServerClaimsChallengeExceptionHandler.class));
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
    void onBehalfOfClientExchangesTheCurrentUsersToken() {
        wireMock.stubFor(post("/" + API_TENANT + "/oauth2/v2.0/token")
                .withRequestBody(containing("requested_token_use=on_behalf_of"))
                .willReturn(okJson("{\"expires_in\":3600,\"access_token\":\"obo-token\"}")));
        runner.withPropertyValues("entra.security.credential.type=client-secret",
                "entra.security.credential.client-secret=top-secret",
                "entra.security.outbound.clients.profile.flow=on-behalf-of",
                "entra.security.outbound.clients.profile.scope=api://profile/Profile.Read api://profile/Profile.Write",
                "entra.security.outbound.clients.profile.base-url=" + wireMock.baseUrl())
                .run(context -> {
                    EntraOutboundClients outbound = context.getBean(EntraOutboundClients.class);
                    assertThat(outbound.flow("profile")).isEqualTo(OutboundFlow.ON_BEHALF_OF);
                    assertThatThrownBy(() -> outbound.tokenProvider("profile"))
                            .hasMessageContaining("on-behalf-of");
                    Jwt user = Jwt.withTokenValue("incoming-user-token").header("alg", "RS256")
                            .claim("oid", "u1").claim("tid", API_TENANT).claim("scp", "access_as_user").build();
                    SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(user));
                    try {
                        RestClient client = RestClient.builder().baseUrl(outbound.baseUrl("profile"))
                                .requestInterceptor(outbound.interceptor("profile")).build();
                        assertThat(client.get().uri("/peer").retrieve().body(String.class)).isEqualTo("pong");
                        String viaWebClient = WebClient.builder().baseUrl(outbound.baseUrl("profile"))
                                .filter(EntraWebClientSupport.filter(outbound, "profile")).build()
                                .get().uri("/peer").retrieve().bodyToMono(String.class).block();
                        assertThat(viaWebClient).isEqualTo("pong");
                        assertThat(outbound.token("profile").value()).isEqualTo("obo-token");
                    }
                    finally {
                        SecurityContextHolder.clearContext();
                    }
                    assertThat(outbound.token("profile", user).value()).isEqualTo("obo-token");
                });
        wireMock.verify(1, postRequestedFor(urlEqualTo("/" + API_TENANT + "/oauth2/v2.0/token"))
                .withRequestBody(containing("assertion=incoming-user-token"))
                .withRequestBody(containing("client_secret=top-secret"))
                .withRequestBody(containing("client_id=22222222-2222-2222-2222-222222222222")));
        wireMock.verify(2, getRequestedFor(urlEqualTo("/peer")).withHeader("Authorization",
                equalTo("Bearer obo-token")));
    }

    @Test
    void onBehalfOfUsesTheApiClientIdEvenWithWorkloadIdentity(@TempDir Path dir) throws Exception {
        Path tokenFile = dir.resolve("azure-identity-token");
        Files.writeString(tokenFile, "projected-sa-token");
        wireMock.stubFor(post("/" + WI_TENANT + "/oauth2/v2.0/token")
                .withRequestBody(containing("requested_token_use=on_behalf_of"))
                .willReturn(okJson("{\"expires_in\":3600,\"access_token\":\"obo-wi\"}")));
        runner.withPropertyValues("entra.security.outbound.clients.profile.flow=on-behalf-of",
                "entra.security.outbound.clients.profile.scope=api://profile/.default",
                "entra.security.outbound.clients.profile.credential.type=workload-identity",
                "AZURE_FEDERATED_TOKEN_FILE=" + tokenFile, "AZURE_CLIENT_ID=77777777-7777-7777-7777-777777777777",
                "AZURE_TENANT_ID=" + WI_TENANT)
                .run(context -> {
                    Jwt user = Jwt.withTokenValue("incoming").header("alg", "RS256")
                            .claim("oid", "u1").claim("scp", "access_as_user").build();
                    assertThat(context.getBean(EntraOutboundClients.class).token("profile", user).value())
                            .isEqualTo("obo-wi");
                });
        wireMock.verify(postRequestedFor(urlEqualTo("/" + WI_TENANT + "/oauth2/v2.0/token"))
                .withRequestBody(containing("client_assertion=projected-sa-token"))
                .withRequestBody(containing("client_id=22222222-2222-2222-2222-222222222222")));
    }

    @Test
    void clientCredentialsClientRefusesOnBehalfOfUse() {
        runner.withPropertyValues("entra.security.credential.type=client-secret",
                "entra.security.credential.client-secret=s",
                "entra.security.outbound.clients.orders.scope=api://orders/.default")
                .run(context -> {
                    EntraOutboundClients outbound = context.getBean(EntraOutboundClients.class);
                    assertThat(outbound.flow("orders")).isEqualTo(OutboundFlow.CLIENT_CREDENTIALS);
                    assertThatThrownBy(() -> outbound.onBehalfOfTokenProvider("orders"))
                            .hasMessageContaining("flow=on-behalf-of");
                });
    }

    @Test
    void interactionRequiredHandlersAreRegisteredForEachWebStack() {
        String[] props = { "entra.security.tenant-id=" + API_TENANT,
                "entra.security.client-id=22222222-2222-2222-2222-222222222222" };
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(EntraOutboundAutoConfiguration.class))
                .withPropertyValues(props)
                .run(context -> {
                    assertThat(context).hasSingleBean(InteractionRequiredExceptionHandler.class);
                    assertThat(context).doesNotHaveBean(ServerInteractionRequiredExceptionHandler.class);
                });
        new ReactiveWebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(EntraOutboundAutoConfiguration.class))
                .withPropertyValues(props)
                .run(context -> {
                    assertThat(context).hasSingleBean(ServerInteractionRequiredExceptionHandler.class);
                    assertThat(context).doesNotHaveBean(InteractionRequiredExceptionHandler.class);
                });
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(InteractionRequiredExceptionHandler.class);
            assertThat(context).doesNotHaveBean(ServerInteractionRequiredExceptionHandler.class);
        });
    }

    @Test
    void unknownClientNameHasHelpfulError() {
        runner.run(context -> assertThatThrownBy(() -> context.getBean(EntraOutboundClients.class).interceptor("x"))
                .hasMessageContaining("entra.security.outbound.clients"));
    }

    @Test
    void routesPickTheClientAndScopeForOnBehalfOfCalls() {
        wireMock.stubFor(post("/" + API_TENANT + "/oauth2/v2.0/token")
                .withRequestBody(containing("Profile.Read"))
                .willReturn(okJson("{\"expires_in\":3600,\"access_token\":\"obo-routed\"}")));
        runner.withPropertyValues("entra.security.credential.type=client-secret",
                "entra.security.credential.client-secret=s",
                "entra.security.outbound.clients.profile.flow=on-behalf-of",
                "entra.security.outbound.clients.profile.scope=api://profile/.default",
                "entra.security.outbound.routes[0].hosts[0]=localhost",
                "entra.security.outbound.routes[0].paths[0]=/peer",
                "entra.security.outbound.routes[0].client=profile",
                "entra.security.outbound.routes[0].scope=api://profile/Profile.Read")
                .run(context -> {
                    EntraOutboundClients outbound = context.getBean(EntraOutboundClients.class);
                    Jwt user = Jwt.withTokenValue("incoming").header("alg", "RS256")
                            .claim("oid", "u1").claim("scp", "access_as_user").build();
                    SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(user));
                    try {
                        RestClient client = RestClient.builder().requestInterceptor(outbound.routingInterceptor())
                                .build();
                        assertThat(client.get().uri(wireMock.baseUrl() + "/peer").retrieve().body(String.class))
                                .isEqualTo("pong");
                        WebClient web = WebClient.builder().filter(EntraWebClientSupport.routingFilter(outbound))
                                .build();
                        assertThat(web.get().uri(wireMock.baseUrl() + "/peer").retrieve().bodyToMono(String.class)
                                .block()).isEqualTo("pong");
                    }
                    finally {
                        SecurityContextHolder.clearContext();
                    }
                });
        wireMock.verify(2, getRequestedFor(urlEqualTo("/peer")).withHeader("Authorization",
                equalTo("Bearer obo-routed")));
    }

    @Test
    void customizersAreRegisteredUnlessTurnedOff() {
        runner.withPropertyValues("entra.security.credential.type=client-secret",
                "entra.security.credential.client-secret=s")
                .run(context -> {
                    assertThat(context).hasBean("entraOutboundRoutingRestClientCustomizer");
                    assertThat(context).hasBean("entraOutboundRoutingWebClientCustomizer");
                    assertThat(context.getBean(EntraOutboundClients.class).hasRoutes()).isFalse();
                    RestClient.Builder builder = RestClient.builder();
                    context.getBean(org.springframework.boot.restclient.RestClientCustomizer.class).customize(builder);
                    WebClient.Builder web = WebClient.builder();
                    context.getBean(org.springframework.boot.webclient.WebClientCustomizer.class)
                            .customize(web);
                    web.filters(filters -> assertThat(filters).isEmpty());
                });
        runner.withPropertyValues("entra.security.outbound.customize-builders=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean("entraOutboundRoutingRestClientCustomizer");
                    assertThat(context).doesNotHaveBean("entraOutboundRoutingWebClientCustomizer");
                });
    }

    @Test
    void customizersAddTheRoutesToBuilders() {
        runner.withPropertyValues("entra.security.credential.type=client-secret",
                "entra.security.credential.client-secret=s",
                "entra.security.outbound.clients.orders.scope=api://orders/.default",
                "entra.security.outbound.routes[0].urls[0]=http://localhost:" + wireMock.port() + "/peer",
                "entra.security.outbound.routes[0].client=orders")
                .run(context -> {
                    RestClient.Builder builder = RestClient.builder();
                    context.getBean(org.springframework.boot.restclient.RestClientCustomizer.class).customize(builder);
                    assertThat(builder.build().get().uri(wireMock.baseUrl() + "/peer").retrieve().body(String.class))
                            .isEqualTo("pong");
                    WebClient.Builder web = WebClient.builder();
                    context.getBean(org.springframework.boot.webclient.WebClientCustomizer.class)
                            .customize(web);
                    web.filters(filters -> assertThat(filters).hasSize(1));
                });
        wireMock.verify(getRequestedFor(urlEqualTo("/peer")).withHeader("Authorization",
                equalTo("Bearer secret-token")));
    }

    @Test
    void invalidRoutesFailAtStartupWithTheProperty() {
        String base = "entra.security.outbound.routes[0].";
        runner.withPropertyValues(base + "hosts[0]=orders.svc", base + "client=missing")
                .run(context -> assertThat(context).getFailure().rootCause()
                        .hasMessageContaining("routes[0].client 'missing' is not configured"));
        runner.withPropertyValues(base + "hosts[0]=orders.svc")
                .run(context -> assertThat(context).getFailure().rootCause()
                        .hasMessageContaining("routes[0].client must name one of"));
        runner.withPropertyValues("entra.security.outbound.clients.orders.scope=api://orders/.default",
                base + "client=orders")
                .run(context -> assertThat(context).getFailure().rootCause()
                        .hasMessageContaining("needs urls or hosts"));
        runner.withPropertyValues("entra.security.outbound.clients.orders.scope=api://orders/.default",
                base + "client=orders", base + "urls[0]=example.text.com/api")
                .run(context -> assertThat(context).getFailure().rootCause()
                        .hasMessageContaining("must start with http:// or https://"));
        runner.withPropertyValues("entra.security.outbound.clients.orders.scope=api://orders/.default",
                base + "client=orders", base + "urls[0]=https://example.text.com", base + "paths[0]=/api/**")
                .run(context -> assertThat(context).getFailure().rootCause()
                        .hasMessageContaining("paths only applies to hosts"));
        runner.withPropertyValues("entra.security.outbound.clients.orders.scope=api://orders/.default",
                base + "client=orders", base + "hosts[0]= ")
                .run(context -> assertThat(context).getFailure().rootCause()
                        .hasMessageContaining("hosts must not contain blank entries"));
        runner.withPropertyValues("entra.security.outbound.skip-hosts[0]=a*b.test")
                .run(context -> assertThat(context).getFailure().rootCause()
                        .hasMessageContaining("skip-hosts[0]"));
    }

    @Test
    void routeToAnUnknownClientIsRefusedProgrammatically() {
        assertThatThrownBy(() -> new EntraOutboundClients(java.util.Map.of(), java.util.List.of(
                new EntraOutboundClients.Route("r", java.util.List.of(), "nope", null)), java.util.List.of()))
                .hasMessageContaining("No outbound client named 'nope'");
    }
}
