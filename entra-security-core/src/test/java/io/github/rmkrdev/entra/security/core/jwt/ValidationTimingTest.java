package io.github.rmkrdev.entra.security.core.jwt;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.test.TestTokens;

/**
 * Measures the authentication work per request (decode, validate, classify, map roles) with warm caches, and
 * the first request after a pre-warmed JWKS. Prints the numbers used in docs/performance.md.
 */
class ValidationTimingTest {

    private static final int ITERATIONS = 2_000;

    private WireMockServer wireMock;
    private TestTokens tokens;

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        tokens = new TestTokens(wireMock.baseUrl());
        wireMock.stubFor(get("/keys").willReturn(okJson(tokens.jwksJson())));
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    @Test
    void warmValidationP99IsWellUnder300Milliseconds() throws Exception {
        try (EntraJwkSource keys = EntraJwtDecoders.refreshingJwkSource(URI.create(wireMock.baseUrl() + "/keys"),
                Duration.ofMinutes(15), Duration.ofSeconds(2), Duration.ofSeconds(3), Duration.ofMinutes(5),
                EntraSecurityObservations.NO_OP)) {
            keys.warm();
            JwtDecoder uncached = EntraJwtDecoders.create(keys, List.of(tokens.v2Issuer()),
                    List.of(TestTokens.CLIENT_ID), TestTokens.TENANT_ID, Duration.ofSeconds(60));
            EntraJwtAuthenticationConverter plainConverter = converter();

            String first = tokens.user().roles("Orders.Read").build();
            long firstStart = System.nanoTime();
            plainConverter.convert(uncached.decode(first));
            double firstMs = (System.nanoTime() - firstStart) / 1e6;

            double[] full = measure(uncached, plainConverter, false);
            CachingJwtDecoder cachedDecoder = new CachingJwtDecoder(uncached, Duration.ofMinutes(5), 10_000,
                    Duration.ofSeconds(60), Clock.systemUTC());
            EntraJwtAuthenticationConverter cachedConverter = converter()
                    .withCache(new AuthenticationCache(Duration.ofMinutes(5), 10_000, Clock.systemUTC()));
            double[] cached = measure(cachedDecoder, cachedConverter, true);

            System.out.printf("auth-timing first-request(prewarmed JWKS)=%.3fms%n", firstMs);
            report("new-token(signature+claims+roles)", full);
            report("repeat-token(cached)", cached);
            assertThat(firstMs).isLessThan(300);
            assertThat(percentile(full, 99)).isLessThan(50);
            assertThat(percentile(cached, 99)).isLessThan(5);
            assertThat(wireMock.getAllServeEvents()).hasSize(1);
        }
    }

    private double[] measure(JwtDecoder decoder, EntraJwtAuthenticationConverter converter, boolean sameToken) {
        String repeated = tokens.user().roles("Orders.Read").build();
        String[] inputs = new String[ITERATIONS];
        for (int i = 0; i < ITERATIONS; i++) {
            inputs[i] = sameToken ? repeated : tokens.user().claim("jti", "j" + i).roles("Orders.Read").build();
        }
        for (int i = 0; i < 500; i++) {
            converter.convert(decoder.decode(inputs[i % ITERATIONS]));
        }
        double[] samples = new double[ITERATIONS];
        for (int i = 0; i < ITERATIONS; i++) {
            long start = System.nanoTime();
            Jwt jwt = decoder.decode(inputs[i]);
            converter.convert(jwt);
            samples[i] = (System.nanoTime() - start) / 1e6;
        }
        Arrays.sort(samples);
        return samples;
    }

    private EntraJwtAuthenticationConverter converter() {
        return new EntraJwtAuthenticationConverter(new EntraTokenClassifier(),
                EntraAuthorityMapper.builder().appRoleMappings(Map.of("Orders.Read", List.of("ORDERS_READ"))).build(),
                null, false, new SafeClaimLogger(false), EntraSecurityObservations.NO_OP);
    }

    private static void report(String label, double[] sorted) {
        System.out.printf("auth-timing %s n=%d p50=%.3fms p95=%.3fms p99=%.3fms max=%.3fms%n", label, sorted.length,
                percentile(sorted, 50), percentile(sorted, 95), percentile(sorted, 99), sorted[sorted.length - 1]);
    }

    private static double percentile(double[] sorted, int p) {
        int index = (int) Math.ceil(p / 100.0 * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(sorted.length - 1, index))];
    }
}
