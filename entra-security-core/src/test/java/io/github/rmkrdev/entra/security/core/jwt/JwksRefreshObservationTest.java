package io.github.rmkrdev.entra.security.core.jwt;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.test.TestTokens;

class JwksRefreshObservationTest {

    private WireMockServer wireMock;
    private TestTokens tokens;

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        tokens = new TestTokens(wireMock.baseUrl());
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    @Test
    void refreshIsReportedOncePerFetch() throws Exception {
        wireMock.stubFor(get("/keys").willReturn(okJson(tokens.jwksJson())));
        List<Boolean> results = new ArrayList<>();
        JWKSource<SecurityContext> source = source(results);
        JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().build());

        assertThat(source.get(selector, null)).hasSize(1);
        assertThat(source.get(selector, null)).hasSize(1);
        assertThat(results).containsExactly(true);
    }

    @Test
    void failedRefreshIsReported() {
        wireMock.stubFor(get("/keys").willReturn(aResponse().withStatus(500)));
        List<Boolean> results = new ArrayList<>();
        JWKSource<SecurityContext> source = source(results);
        assertThatThrownBy(() -> source.get(new JWKSelector(new JWKMatcher.Builder().build()), null))
                .isInstanceOf(Exception.class);
        assertThat(results).isNotEmpty().allMatch(success -> !success);
    }

    private JWKSource<SecurityContext> source(List<Boolean> results) {
        return EntraJwtDecoders.jwkSource(URI.create(wireMock.baseUrl() + "/keys"), Duration.ofMinutes(15),
                Duration.ofSeconds(5), new EntraSecurityObservations() {
                    @Override
                    public void jwksRefresh(boolean success, Duration duration) {
                        assertThat(duration).isGreaterThanOrEqualTo(Duration.ZERO);
                        results.add(success);
                    }
                });
    }
}
