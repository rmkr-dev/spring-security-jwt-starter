package io.github.rmkrdev.entra.security.core.jwt;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.core.test.TestTokens;

class JwtAuthenticationOutcomesTest {

    private static WireMockServer wireMock;
    private static TestTokens tokens;
    private static JwtDecoder decoder;

    @BeforeAll
    static void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        tokens = new TestTokens(wireMock.baseUrl());
        wireMock.stubFor(get("/" + TestTokens.TENANT_ID + "/discovery/v2.0/keys")
                .willReturn(okJson(tokens.jwksJson())));
        decoder = EntraJwtDecoders.create(
                EntraJwtDecoders.jwkSource(URI.create(wireMock.baseUrl() + "/" + TestTokens.TENANT_ID
                        + "/discovery/v2.0/keys"), Duration.ofMinutes(5), Duration.ofSeconds(5)),
                List.of(tokens.v2Issuer()), List.of(TestTokens.CLIENT_ID), TestTokens.TENANT_ID,
                Duration.ofSeconds(30));
    }

    @AfterAll
    static void stop() {
        wireMock.stop();
    }

    @Test
    void reasonsStayInsideAFixedSet() {
        assertThat(reason(tokens.user().issuedAt(Instant.now().minus(Duration.ofHours(2)))
                .expiresAt(Instant.now().minus(Duration.ofHours(1))).build()))
                .isEqualTo(JwtAuthenticationOutcomes.EXPIRED);
        assertThat(reason(tokens.user().issuedAt(Instant.now().plus(Duration.ofHours(1)))
                .expiresAt(Instant.now().plus(Duration.ofHours(2))).build()))
                .isEqualTo(JwtAuthenticationOutcomes.NOT_YET_VALID);
        assertThat(reason(tokens.user().issuer("https://evil.example/").build()))
                .isEqualTo(JwtAuthenticationOutcomes.INVALID_ISSUER);
        assertThat(reason(tokens.user().audience("someone-else").build()))
                .isEqualTo(JwtAuthenticationOutcomes.INVALID_AUDIENCE);
        assertThat(reason(tokens.user().claim("tid", "99999999-9999-9999-9999-999999999999").build()))
                .isEqualTo(JwtAuthenticationOutcomes.INVALID_TENANT);
        assertThat(JwtAuthenticationOutcomes.reason(new BadJwtException("The exp claim is required")))
                .isEqualTo(JwtAuthenticationOutcomes.MISSING_CLAIMS);
        assertThat(reason(tokens.user().signedWithUnknownKey().build()))
                .isEqualTo(JwtAuthenticationOutcomes.INVALID_SIGNATURE);
        assertThat(reason(tokens.user().hmac().build())).isEqualTo(JwtAuthenticationOutcomes.UNKNOWN_KEY);
        assertThat(reason("not-a-jwt")).isEqualTo(JwtAuthenticationOutcomes.MALFORMED);
        assertThat(JwtAuthenticationOutcomes.reason(
                new InvalidBearerTokenException("The calling client application is not allowed to call this API")))
                .isEqualTo(JwtAuthenticationOutcomes.CLIENT_NOT_ALLOWED);
        assertThat(JwtAuthenticationOutcomes.reason(new JwtException(EntraAccessTokenValidator.DESCRIPTION)))
                .isEqualTo(JwtAuthenticationOutcomes.NOT_ACCESS_TOKEN);
        assertThat(JwtAuthenticationOutcomes.reason(new JwtException("something unexpected")))
                .isEqualTo(JwtAuthenticationOutcomes.INVALID_TOKEN);
        assertThat(JwtAuthenticationOutcomes.isKnown("oid-value")).isFalse();
    }

    private static String reason(String token) {
        Throwable failure = catchThrowable(() -> decoder.decode(token));
        assertThat(failure).as("%s", failure).isInstanceOf(JwtException.class);
        return JwtAuthenticationOutcomes.reason(failure);
    }
}
