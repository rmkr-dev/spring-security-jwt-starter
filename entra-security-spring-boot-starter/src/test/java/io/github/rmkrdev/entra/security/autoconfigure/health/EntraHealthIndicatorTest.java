package io.github.rmkrdev.entra.security.autoconfigure.health;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.rmkrdev.entra.security.core.token.AccessToken;
import io.github.rmkrdev.entra.security.core.token.EntraTokenAcquisitionException;

class EntraHealthIndicatorTest {

    private static final String SECRET_TOKEN = "graph-token-secret";

    private WireMockServer wireMock;

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
    }

    @AfterEach
    void stop() {
        if (wireMock.isRunning()) {
            wireMock.stop();
        }
    }

    @Test
    void jwksIsUpWhenASigningKeyIsCached() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("kid").generate();
        JWKSource<SecurityContext> source = (selector, context) -> selector.select(new JWKSet(key.toPublicJWK()));
        Health health = new EntraJwksHealthIndicator(source).health();
        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("keys", 1);
    }

    @Test
    void jwksIsDownWithoutUsableKeys() {
        JWKSource<SecurityContext> empty = (selector, context) -> List.<JWK>of();
        Health health = new EntraJwksHealthIndicator(empty).health();
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("reason", "no_signing_keys");
    }

    @Test
    void jwksIsDownWhenTheSourceFails() {
        JWKSource<SecurityContext> failing = (selector, context) -> {
            throw new IllegalStateException("jwks down");
        };
        Health health = new EntraJwksHealthIndicator(failing).health();
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("reason", "unreachable");
        assertThat(health.getDetails().toString()).contains("jwks down");
    }

    @Test
    void graphIsUpWhenTheServiceRootAcceptsTheCredential() {
        wireMock.stubFor(get(urlPathEqualTo("/v1.0/")).willReturn(ok()));
        Health health = graph(scope -> new AccessToken(SECRET_TOKEN, Instant.now().plusSeconds(60))).health();
        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails().toString()).doesNotContain(SECRET_TOKEN);
    }

    @Test
    void graphIsDownWhenTheCredentialIsRejected() {
        wireMock.stubFor(get(urlPathEqualTo("/v1.0/")).willReturn(aResponse().withStatus(401)));
        Health health = graph(scope -> new AccessToken(SECRET_TOKEN, Instant.now().plusSeconds(60))).health();
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("reason", "unauthorized").containsEntry("status", 401);
        assertThat(health.getDetails().toString()).doesNotContain(SECRET_TOKEN);
    }

    @Test
    void graphIsDownWhenTheTokenCannotBeAcquired() {
        Health health = graph(scope -> {
            throw new EntraTokenAcquisitionException("token endpoint failed", "invalid_client", null);
        }).health();
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("reason", "token");
        assertThat(health.getDetails().toString()).doesNotContain(SECRET_TOKEN);
    }

    @Test
    void graphIsDownWhenTheEndpointIsUnreachable() {
        int port = wireMock.port();
        wireMock.stop();
        Health health = graph(URI.create("http://127.0.0.1:" + port),
                scope -> new AccessToken(SECRET_TOKEN, Instant.now().plusSeconds(60))).health();
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("reason", "unreachable");
    }

    private EntraGraphHealthIndicator graph(
            io.github.rmkrdev.entra.security.core.token.EntraTokenProvider tokenProvider) {
        return graph(URI.create(wireMock.baseUrl()), tokenProvider);
    }

    private EntraGraphHealthIndicator graph(URI baseUrl,
            io.github.rmkrdev.entra.security.core.token.EntraTokenProvider tokenProvider) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(2));
        factory.setReadTimeout(Duration.ofSeconds(2));
        return new EntraGraphHealthIndicator(tokenProvider, RestClient.builder().requestFactory(factory).build(),
                baseUrl, "https://graph.microsoft.com/.default");
    }
}
