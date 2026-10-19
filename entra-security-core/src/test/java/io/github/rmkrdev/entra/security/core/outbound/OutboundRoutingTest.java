package io.github.rmkrdev.entra.security.core.outbound;

import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.core.token.AccessToken;
import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;

class OutboundRoutingTest {

    private final EntraTokenProvider provider = scope -> new AccessToken("tok-" + scope,
            Instant.now().plusSeconds(600));
    private WireMockServer wireMock;
    private String base;

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        wireMock.stubFor(any(anyUrl()).willReturn(ok("ok")));
        base = "http://localhost:" + wireMock.port();
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    private List<OutboundTarget> skip() {
        return List.of(OutboundTarget.host("localhost:" + (wireMock.port() == 1 ? 2 : 1), null, List.of()));
    }

    @Test
    void routerPicksTheFirstMatchAndHonoursSkipHosts() {
        OutboundRouter<String> router = new OutboundRouter<>(List.of(
                new OutboundRouter.Route<>("narrow", List.of(OutboundTarget.url("https://a.test/admin/**")), "A1"),
                new OutboundRouter.Route<>("broad", List.of(OutboundTarget.host("*.test", null, List.of())), "A2")),
                List.of(OutboundTarget.host("public.test", null, List.of())));
        assertThat(router.route(URI.create("https://a.test/admin/x")).map(OutboundRouter.Route::value)).hasValue("A1");
        assertThat(router.route(URI.create("https://a.test/other")).map(OutboundRouter.Route::value)).hasValue("A2");
        assertThat(router.route(URI.create("https://public.test/other"))).isEmpty();
        assertThat(router.route(URI.create("https://a.example/other"))).isEmpty();
        assertThat(router.isSkipped(URI.create("https://public.test/"))).isTrue();
        assertThat(router.routes()).hasSize(2);
    }

    @Test
    void restClientGetsTheTokenOfTheMatchingRoute() {
        OutboundRouter<ClientHttpRequestInterceptor> router = new OutboundRouter<>(List.of(
                new OutboundRouter.Route<>("a", List.of(OutboundTarget.url(base + "/a/**")),
                        new EntraBearerTokenInterceptor(provider, "scope-a")),
                new OutboundRouter.Route<>("b", List.of(OutboundTarget.host("localhost", null, List.of("/b/**"))),
                        new EntraBearerTokenInterceptor(provider, "scope-b"))), skip());
        RestClient client = RestClient.builder().requestInterceptor(new EntraRoutingInterceptor(router)).build();

        client.get().uri(base + "/a/1").retrieve().toBodilessEntity();
        client.get().uri(base + "/b/1").retrieve().toBodilessEntity();
        client.get().uri(base + "/c/1").retrieve().toBodilessEntity();
        client.get().uri(base + "/a/2").header("Authorization", "Bearer mine").retrieve().toBodilessEntity();

        wireMock.verify(getRequestedFor(urlEqualTo("/a/1")).withHeader("Authorization", equalTo("Bearer tok-scope-a")));
        wireMock.verify(getRequestedFor(urlEqualTo("/b/1")).withHeader("Authorization", equalTo("Bearer tok-scope-b")));
        wireMock.verify(getRequestedFor(urlEqualTo("/c/1")).withHeader("Authorization", absent()));
        wireMock.verify(getRequestedFor(urlEqualTo("/a/2")).withHeader("Authorization", equalTo("Bearer mine")));
    }

    @Test
    void skippedHostsNeverGetAToken() {
        OutboundRouter<ClientHttpRequestInterceptor> router = new OutboundRouter<>(List.of(
                new OutboundRouter.Route<>("all", List.of(OutboundTarget.host("*", true, List.of())),
                        new EntraBearerTokenInterceptor(provider, "s"))),
                List.of(OutboundTarget.host("localhost", null, List.of())));
        RestClient.builder().requestInterceptor(new EntraRoutingInterceptor(router)).build()
                .get().uri(base + "/public").retrieve().toBodilessEntity();
        wireMock.verify(getRequestedFor(urlEqualTo("/public")).withHeader("Authorization", absent()));
    }

    @Test
    void webClientGetsTheTokenOfTheMatchingRoute() {
        OutboundRouter<ExchangeFilterFunction> router = new OutboundRouter<>(List.of(
                new OutboundRouter.Route<>("a", List.of(OutboundTarget.url(base + "/a/**")),
                        new EntraBearerExchangeFilterFunction(provider, "scope-a"))), skip());
        WebClient client = WebClient.builder().filter(new EntraRoutingExchangeFilterFunction(router)).build();

        client.get().uri(base + "/a/1").retrieve().toBodilessEntity().block();
        client.get().uri(base + "/c/1").retrieve().toBodilessEntity().block();
        client.get().uri(base + "/a/2").header("Authorization", "Bearer mine").retrieve().toBodilessEntity().block();

        wireMock.verify(getRequestedFor(urlEqualTo("/a/1")).withHeader("Authorization", equalTo("Bearer tok-scope-a")));
        wireMock.verify(getRequestedFor(urlEqualTo("/c/1")).withHeader("Authorization", absent()));
        wireMock.verify(getRequestedFor(urlEqualTo("/a/2")).withHeader("Authorization", equalTo("Bearer mine")));
    }
}
