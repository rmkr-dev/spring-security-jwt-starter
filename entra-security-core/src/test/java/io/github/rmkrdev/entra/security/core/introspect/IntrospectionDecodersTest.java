package io.github.rmkrdev.entra.security.core.introspect;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import io.github.rmkrdev.entra.security.core.introspect.HybridJwtDecoder.Strategy;
import io.github.rmkrdev.entra.security.core.test.TestTokens;

class IntrospectionDecodersTest {

    static final TestTokens TOKENS = new TestTokens("https://login.example");

    @Test
    void activeTokenBecomesAJwtWithMappedClaims() {
        long exp = Instant.now().plusSeconds(600).getEpochSecond();
        IntrospectionJwtDecoder decoder = new IntrospectionJwtDecoder(
                token -> IntrospectionResult.active(Map.of("sub", "u", "scope", "Orders.Read", "client_id", "app",
                        "exp", exp, "iat", "1700000000", "nbf", "later", "uid", "o-1")),
                IntrospectedClaimsMapper.rfc7662(Map.of("oid", "uid")), null);

        Jwt jwt = decoder.decode("opaque");

        assertThat(jwt.getTokenValue()).isEqualTo("opaque");
        assertThat(jwt.getHeaders()).containsEntry("alg", "none").containsEntry("typ", "introspected");
        assertThat(jwt.getClaimAsString("scp")).isEqualTo("Orders.Read");
        assertThat(jwt.getClaimAsString("azp")).isEqualTo("app");
        assertThat(jwt.getClaimAsString("oid")).isEqualTo("o-1");
        assertThat(jwt.getExpiresAt()).isEqualTo(Instant.ofEpochSecond(exp));
        assertThat(jwt.getIssuedAt()).isEqualTo(Instant.ofEpochSecond(1_700_000_000L));
        assertThat(jwt.getNotBefore()).isNull();
    }

    @Test
    void inconsistentTimestampsAreInvalidTokens() {
        IntrospectionJwtDecoder decoder = new IntrospectionJwtDecoder(token -> IntrospectionResult.active(
                Map.of("sub", "u", "iat", 2_000_000_000L, "exp", 1_900_000_000L)),
                IntrospectedClaimsMapper.rfc7662(null), null);
        assertThatThrownBy(() -> decoder.decode("t")).isInstanceOf(BadJwtException.class)
                .hasMessageContaining("inconsistent");
    }

    @Test
    void userInfoMappingMakesAUserToken() {
        Map<String, Object> mapped = IntrospectedClaimsMapper.userInfo(null).map(Map.of("id", "o-1",
                "userPrincipalName", "a@contoso.com", "displayName", "A"));
        assertThat(mapped).containsEntry("oid", "o-1").containsEntry("preferred_username", "a@contoso.com")
                .containsEntry("name", "A").containsEntry("idtyp", "user");
        // An existing target claim is never overwritten.
        assertThat(IntrospectedClaimsMapper.rfc7662(null).map(Map.of("scope", "x", "scp", "y")))
                .containsEntry("scp", "y");
        assertThat(new IntrospectedClaimsMapper(null, null).map(Map.of("a", 1))).containsOnlyKeys("a");
    }

    @Test
    void inactiveEmptyAndUnavailableAreInvalidTokens() {
        assertThatThrownBy(() -> new IntrospectionJwtDecoder(token -> IntrospectionResult.inactive(),
                IntrospectedClaimsMapper.rfc7662(null), null).decode("t"))
                .isInstanceOf(BadJwtException.class).hasMessageContaining("not active");
        assertThatThrownBy(() -> new IntrospectionJwtDecoder(token -> IntrospectionResult.active(Map.of()),
                new IntrospectedClaimsMapper(Map.of(), Map.of()), null).decode("t"))
                .isInstanceOf(BadJwtException.class).hasMessageContaining("no claims");
        assertThatThrownBy(() -> new IntrospectionJwtDecoder(token -> {
            throw new IntrospectionException("down", null);
        }, IntrospectedClaimsMapper.rfc7662(null), null).decode("t"))
                .isInstanceOf(BadJwtException.class).hasMessageContaining("unavailable");
        assertThatThrownBy(() -> new IntrospectionJwtDecoder(token -> IntrospectionResult.inactive(),
                IntrospectedClaimsMapper.rfc7662(null), null).decode(" "))
                .isInstanceOf(BadJwtException.class);
    }

    @Test
    void validatorRunsOnTheMappedClaims() {
        IntrospectionJwtDecoder decoder = new IntrospectionJwtDecoder(
                token -> IntrospectionResult.active(Map.of("sub", "u", "aud", "other")),
                IntrospectedClaimsMapper.rfc7662(null),
                jwt -> jwt.getAudience().contains("mine") ? OAuth2TokenValidatorResult.success()
                        : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "wrong audience", null)));
        assertThatThrownBy(() -> decoder.decode("t")).isInstanceOf(JwtValidationException.class)
                .hasMessageContaining("wrong audience");
    }

    @Test
    void hybridBothNeedsLocalAndRemote() {
        AtomicInteger remoteCalls = new AtomicInteger();
        JwtDecoder local = token -> {
            if (token.startsWith("bad")) {
                throw new BadJwtException("signature");
            }
            return Jwt.withTokenValue(token).header("alg", "RS256").claim("sub", "s").build();
        };
        TokenIntrospector remote = token -> {
            remoteCalls.incrementAndGet();
            return token.endsWith("revoked") ? IntrospectionResult.inactive()
                    : IntrospectionResult.active(Map.of("sub", "s"));
        };
        HybridJwtDecoder decoder = new HybridJwtDecoder(local, remote, null, Strategy.BOTH);

        assertThat(decoder.decode("good").getHeaders()).containsEntry("alg", "RS256");
        assertThatThrownBy(() -> decoder.decode("good-revoked")).hasMessageContaining("no longer active");
        assertThatThrownBy(() -> decoder.decode("bad")).hasMessage("signature");
        assertThat(remoteCalls).hasValue(2);
        assertThat(decoder.getStrategy()).isEqualTo(Strategy.BOTH);
    }

    @Test
    void hybridFallbackOnlyForOpaqueTokens() {
        JwtDecoder local = token -> Jwt.withTokenValue(token).header("alg", "RS256").claim("src", "local").build();
        JwtDecoder remote = token -> Jwt.withTokenValue(token).header("alg", "none").claim("src", "remote").build();
        HybridJwtDecoder decoder = new HybridJwtDecoder(local, null, remote, Strategy.FALLBACK);

        assertThat(decoder.decode(TOKENS.user().build()).getClaimAsString("src")).isEqualTo("local");
        assertThat(decoder.decode("opaque-reference-token").getClaimAsString("src")).isEqualTo("remote");
    }

    @Test
    void circuitBreakerStates() {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-19T00:00:00Z"));
        IntrospectionCircuitBreaker breaker = new IntrospectionCircuitBreaker(2, Duration.ofSeconds(30), clock);
        assertThat(breaker.tryAcquire()).isTrue();
        breaker.onFailure();
        assertThat(breaker.state()).isEqualTo(IntrospectionCircuitBreaker.State.CLOSED);
        breaker.onFailure();
        assertThat(breaker.state()).isEqualTo(IntrospectionCircuitBreaker.State.OPEN);
        assertThat(breaker.tryAcquire()).isFalse();

        clock.advance(Duration.ofSeconds(31));
        assertThat(breaker.state()).isEqualTo(IntrospectionCircuitBreaker.State.HALF_OPEN);
        assertThat(breaker.tryAcquire()).isTrue();
        assertThat(breaker.tryAcquire()).isFalse();
        breaker.onFailure();
        assertThat(breaker.state()).isEqualTo(IntrospectionCircuitBreaker.State.OPEN);

        clock.advance(Duration.ofSeconds(31));
        assertThat(breaker.tryAcquire()).isTrue();
        breaker.onSuccess();
        assertThat(breaker.state()).isEqualTo(IntrospectionCircuitBreaker.State.CLOSED);
        assertThat(breaker.tryAcquire()).isTrue();
        assertThatIllegalArgumentException().isThrownBy(() -> new IntrospectionCircuitBreaker(0,
                Duration.ofSeconds(1), clock));
    }
}
