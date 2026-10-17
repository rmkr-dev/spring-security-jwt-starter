package io.github.rmkrdev.entra.security.core.outbound;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.core.token.AccessToken;
import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;

class OutboundInterceptorTest {

    private WireMockServer wireMock;
    private final EntraTokenProvider provider = scope -> new AccessToken("tok-for-" + scope.length(),
            Instant.now().plusSeconds(600));

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        wireMock.stubFor(get("/peer").willReturn(ok("pong")));
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    @Test
    void restClientInterceptorAddsBearer() {
        String body = RestClient.builder().baseUrl(wireMock.baseUrl())
                .requestInterceptor(new EntraBearerTokenInterceptor(provider, "abc"))
                .build().get().uri("/peer").retrieve().body(String.class);
        assertThat(body).isEqualTo("pong");
        wireMock.verify(getRequestedFor(urlEqualTo("/peer")).withHeader("Authorization", equalTo("Bearer tok-for-3")));
    }

    @Test
    void webClientFilterAddsBearer() {
        String body = WebClient.builder().baseUrl(wireMock.baseUrl())
                .filter(new EntraBearerExchangeFilterFunction(provider, "abcd"))
                .build().get().uri("/peer").retrieve().bodyToMono(String.class).block();
        assertThat(body).isEqualTo("pong");
        wireMock.verify(getRequestedFor(urlEqualTo("/peer")).withHeader("Authorization", equalTo("Bearer tok-for-4")));
    }
}
