package io.github.rmkrdev.entra.security.core.jwt;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;

import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.cache.TokenKeys;
import io.github.rmkrdev.entra.security.core.graph.GroupMembership;
import io.github.rmkrdev.entra.security.core.graph.ReactiveGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.test.TestTokens;

import reactor.core.publisher.Mono;

class PerformanceCachesTest {

    private WireMockServer wireMock;
    private TestTokens tokens;
    private final MutableClock clock = new MutableClock(Instant.now());

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
    void tokenKeysAreStableHashesNotTheToken() {
        assertThat(TokenKeys.of("abc")).isEqualTo(TokenKeys.of("abc")).isNotEqualTo(TokenKeys.of("abd"))
                .doesNotContain("abc").hasSize(43);
    }

    @Test
    void cachingDecoderSkipsDelegateUntilExpiryAndNeverCachesFailures() {
        AtomicInteger calls = new AtomicInteger();
        Instant exp = clock.instant().plusSeconds(120);
        JwtDecoder delegate = token -> {
            calls.incrementAndGet();
            if (token == null || token.startsWith("bad")) {
                throw new JwtException("bad");
            }
            return jwt(token, exp);
        };
        CachingJwtDecoder decoder = new CachingJwtDecoder(delegate, Duration.ofMinutes(5), 10, Duration.ofSeconds(30),
                clock);
        assertThat(decoder.decode("good").getTokenValue()).isEqualTo("good");
        assertThat(decoder.decode("good").getTokenValue()).isEqualTo("good");
        assertThat(calls).hasValue(1);
        assertThat(decoder.size()).isEqualTo(1);
        assertThat(decoder.getDelegate()).isSameAs(delegate);

        assertThatThrownBy(() -> decoder.decode("bad")).isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> decoder.decode("bad")).isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> decoder.decode(null)).isInstanceOf(JwtException.class);
        assertThat(calls).hasValue(4);

        clock.advance(Duration.ofSeconds(151));
        decoder.decode("good");
        assertThat(calls).hasValue(5);
    }

    @Test
    void cachingDecoderIgnoresTokensWithoutExpiry() {
        AtomicInteger calls = new AtomicInteger();
        CachingJwtDecoder decoder = new CachingJwtDecoder(token -> {
            calls.incrementAndGet();
            return Jwt.withTokenValue(token).header("alg", "none").claim("sub", "s").build();
        }, Duration.ofMinutes(5), 10, null, clock);
        decoder.decode("x");
        decoder.decode("x");
        assertThat(calls).hasValue(2);
    }

    @Test
    void servletConverterReusesMappingAndRetriesFailedGraphLookups() {
        AtomicInteger graphCalls = new AtomicInteger();
        AtomicInteger failures = new AtomicInteger(1);
        AuthenticationCache cache = new AuthenticationCache(Duration.ofMinutes(5), 100, clock);
        EntraJwtAuthenticationConverter converter = new EntraJwtAuthenticationConverter(new EntraTokenClassifier(),
                mapper(), (tid, oid) -> {
                    graphCalls.incrementAndGet();
                    if (failures.getAndDecrement() > 0) {
                        throw new IllegalStateException("graph down");
                    }
                    return List.of(new GroupMembership("g-9", "Big Group"));
                }, false, new SafeClaimLogger(false), EntraSecurityObservations.NO_OP).withCache(cache);
        Jwt jwt = overageJwt("o-1");

        EntraAuthenticationToken failed = (EntraAuthenticationToken) converter.convert(jwt);
        assertThat(failed.getAuthorities()).isEmpty();
        assertThat(cache.size()).isZero();

        EntraAuthenticationToken first = (EntraAuthenticationToken) converter.convert(jwt);
        EntraAuthenticationToken second = (EntraAuthenticationToken) converter.convert(jwt);
        assertThat(second).isNotSameAs(first);
        assertThat(second.getAuthorities()).extracting("authority").containsExactly("ROLE_BIG");
        assertThat(second.getEntraPrincipal()).isEqualTo(first.getEntraPrincipal());
        assertThat(graphCalls).hasValue(2);
        assertThat(cache.size()).isEqualTo(1);
    }

    @Test
    void reactiveConverterReusesMapping() {
        AtomicInteger graphCalls = new AtomicInteger();
        AtomicInteger failures = new AtomicInteger(1);
        AuthenticationCache cache = new AuthenticationCache(Duration.ofMinutes(5), 100, clock);
        ReactiveGroupMembershipResolver resolver = (tid, oid) -> Mono.fromSupplier(() -> {
            graphCalls.incrementAndGet();
            if (failures.getAndDecrement() > 0) {
                throw new IllegalStateException("graph down");
            }
            return List.of(new GroupMembership("g-9", "Big Group"));
        });
        ReactiveEntraJwtAuthenticationConverter converter = new ReactiveEntraJwtAuthenticationConverter(
                new EntraTokenClassifier(), mapper(), resolver, false, new SafeClaimLogger(false),
                EntraSecurityObservations.NO_OP).withCache(cache);
        Jwt jwt = overageJwt("o-2");
        assertThat(converter.convert(jwt).block().getAuthorities()).isEmpty();
        assertThat(converter.convert(jwt).block().getAuthorities()).extracting("authority")
                .containsExactly("ROLE_BIG");
        assertThat(converter.convert(jwt).block().getAuthorities()).extracting("authority")
                .containsExactly("ROLE_BIG");
        assertThat(graphCalls).hasValue(2);

        Jwt plain = EntraTokenClassifierTest.jwt(Map.of("scp", "s", "oid", "o-3", "tid", "t",
                "groups", List.of("g-1")));
        assertThat(converter.convert(plain).block().getAuthorities()).extracting("authority")
                .containsExactly("ROLE_READER");
        assertThat(cache.size()).isEqualTo(2);
    }

    @Test
    void authenticationCacheSkipsTokensWithoutExpiry() {
        AuthenticationCache cache = new AuthenticationCache(Duration.ofMinutes(5), 10, clock);
        Jwt noExp = Jwt.withTokenValue("n").header("alg", "none").claim("sub", "s").build();
        EntraAuthenticationToken auth = (EntraAuthenticationToken) new EntraJwtAuthenticationConverter(
                new EntraTokenClassifier(), mapper(), null, false, new SafeClaimLogger(false)).convert(
                        EntraTokenClassifierTest.jwt(Map.of("scp", "s", "oid", "o", "tid", "t")));
        cache.put(noExp, auth);
        assertThat(cache.get(noExp)).isNull();
    }

    @Test
    void jwkSourceWarmsOnceAndRefreshesInBackground() throws Exception {
        wireMock.stubFor(get("/keys").willReturn(okJson(tokens.jwksJson())));
        try (EntraJwkSource source = EntraJwtDecoders.refreshingJwkSource(URI.create(wireMock.baseUrl() + "/keys"),
                Duration.ofSeconds(4), Duration.ofSeconds(2), Duration.ofSeconds(3), Duration.ofSeconds(2),
                EntraSecurityObservations.NO_OP)) {
            assertThat(source.isRefreshingAhead()).isTrue();
            assertThat(source.getJwksUri().getPath()).isEqualTo("/keys");
            assertThat(source.warm()).isEqualTo(1);
            assertThat(source.get(new JWKSelector(new JWKMatcher.Builder().keyID("test-kid").build()), null))
                    .hasSize(1);
            wireMock.verify(1, getRequestedFor(urlEqualTo("/keys")));
            Thread.sleep(4500);
            assertThat(wireMock.countRequestsMatching(getRequestedFor(urlEqualTo("/keys")).build()).getCount())
                    .isGreaterThanOrEqualTo(2);
        }
    }

    @Test
    void jwkSourceWithoutRefreshAheadAndFailures() throws Exception {
        wireMock.stubFor(get("/keys").willReturn(aResponse().withStatus(500)));
        try (EntraJwkSource source = EntraJwtDecoders.refreshingJwkSource(URI.create(wireMock.baseUrl() + "/keys"),
                Duration.ofMinutes(5), Duration.ofSeconds(2), Duration.ofSeconds(3), Duration.ZERO,
                new EntraSecurityObservations() {
                })) {
            assertThat(source.isRefreshingAhead()).isFalse();
            assertThatThrownBy(source::warm).isInstanceOf(Exception.class);
        }
        assertThatThrownBy(() -> new EntraJwkSource(URI.create("urn:x"), null, Duration.ofMinutes(1),
                Duration.ofSeconds(1), null)).isInstanceOf(IllegalArgumentException.class);
    }

    private EntraAuthorityMapper mapper() {
        return EntraAuthorityMapper.builder()
                .groupRoleMappings(Map.of("g-1", List.of("READER"), "Big Group", List.of("BIG")))
                .build();
    }

    private Jwt overageJwt(String oid) {
        return Jwt.withTokenValue("token-" + oid).header("alg", "RS256").claim("scp", "s").claim("oid", oid)
                .claim("tid", "t").claim("sub", "s").claim("_claim_names", Map.of("groups", "src1"))
                .issuedAt(clock.instant()).expiresAt(clock.instant().plusSeconds(600)).build();
    }

    private static Jwt jwt(String token, Instant exp) {
        return Jwt.withTokenValue(token).header("alg", "RS256").claim("sub", "s").expiresAt(exp).build();
    }

    static final class MutableClock extends Clock {

        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
