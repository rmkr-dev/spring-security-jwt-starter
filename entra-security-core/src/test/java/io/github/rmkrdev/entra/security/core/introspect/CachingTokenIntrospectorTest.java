package io.github.rmkrdev.entra.security.core.introspect;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;

class CachingTokenIntrospectorTest {

    final MutableClock clock = new MutableClock(Instant.parse("2026-10-19T00:00:00Z"));
    final AtomicInteger calls = new AtomicInteger();
    final List<String> results = new ArrayList<>();
    final EntraSecurityObservations observations = new EntraSecurityObservations() {
        @Override
        public void introspection(String result, Duration duration) {
            results.add(result);
        }
    };

    CachingTokenIntrospector caching(TokenIntrospector delegate) {
        return new CachingTokenIntrospector(token -> {
            calls.incrementAndGet();
            return delegate.introspect(token);
        }, Duration.ofMinutes(5), Duration.ofSeconds(10), 100, new IntrospectionCircuitBreaker(2,
                Duration.ofSeconds(30), clock), clock, observations);
    }

    @Test
    void activeResultsAreCachedUntilTheEarlierOfExpAndTtl() {
        long exp = clock.instant().plusSeconds(60).getEpochSecond();
        CachingTokenIntrospector introspector = caching(token -> IntrospectionResult.active(Map.of("exp", exp)));

        introspector.introspect("a");
        introspector.introspect("a");
        assertThat(calls).hasValue(1);
        assertThat(introspector.cachedResults()).isEqualTo(1);

        clock.advance(Duration.ofSeconds(61));
        introspector.introspect("a");
        assertThat(calls).hasValue(2);
        assertThat(results).containsExactly("active", "active");
    }

    @Test
    void withoutExpTheTtlApplies() {
        CachingTokenIntrospector introspector = caching(token -> IntrospectionResult.active(Map.of("sub", "s")));
        introspector.introspect("a");
        clock.advance(Duration.ofMinutes(4));
        introspector.introspect("a");
        assertThat(calls).hasValue(1);
        clock.advance(Duration.ofMinutes(2));
        introspector.introspect("a");
        assertThat(calls).hasValue(2);
    }

    @Test
    void unverifiedJwtExpiryBoundsTheCache() {
        String jwt = new PlainJWT(new PlainHeader(), new JWTClaimsSet.Builder()
                .expirationTime(Date.from(clock.instant().plusSeconds(20))).build()).serialize();
        CachingTokenIntrospector introspector = caching(token -> IntrospectionResult.active(Map.of("sub", "s")));
        introspector.introspect(jwt);
        clock.advance(Duration.ofSeconds(21));
        introspector.introspect(jwt);
        assertThat(calls).hasValue(2);
    }

    @Test
    void expiredTokensAreNotCached() {
        CachingTokenIntrospector introspector = caching(token -> IntrospectionResult.active(
                Map.of("exp", clock.instant().minusSeconds(5))));
        introspector.introspect("a");
        introspector.introspect("a");
        assertThat(calls).hasValue(2);
    }

    @Test
    void inactiveResultsAreCachedBriefly() {
        CachingTokenIntrospector introspector = caching(token -> IntrospectionResult.inactive());
        assertThat(introspector.introspect("bad").active()).isFalse();
        introspector.introspect("bad");
        assertThat(calls).hasValue(1);
        clock.advance(Duration.ofSeconds(11));
        introspector.introspect("bad");
        assertThat(calls).hasValue(2);
        assertThat(results).containsExactly("inactive", "inactive");
    }

    @Test
    void failuresOpenTheCircuitAndFailClosed() {
        CachingTokenIntrospector introspector = caching(token -> {
            throw new IntrospectionException("down", null);
        });
        assertThatThrownBy(() -> introspector.introspect("a")).isInstanceOf(IntrospectionException.class)
                .hasMessage("down");
        assertThatThrownBy(() -> introspector.introspect("a")).isInstanceOf(IntrospectionException.class);
        assertThat(introspector.circuitBreaker().state()).isEqualTo(IntrospectionCircuitBreaker.State.OPEN);

        assertThatThrownBy(() -> introspector.introspect("a")).hasMessageContaining("circuit breaker is open");
        assertThat(calls).hasValue(2);
        assertThat(results).containsExactly("error", "error", "rejected");
    }

    @Test
    void unexpectedExceptionsAreWrapped() {
        CachingTokenIntrospector introspector = caching(token -> {
            throw new IllegalStateException("boom");
        });
        assertThatThrownBy(() -> introspector.introspect("a")).isInstanceOf(IntrospectionException.class)
                .hasMessageContaining("boom").hasCauseInstanceOf(IllegalStateException.class);
    }

    @Test
    void cachedResultsSurviveAnOpenCircuit() {
        AtomicInteger mode = new AtomicInteger();
        CachingTokenIntrospector introspector = caching(token -> {
            if (mode.get() == 1) {
                throw new IntrospectionException("down", null);
            }
            return IntrospectionResult.active(Map.of("sub", token));
        });
        introspector.introspect("cached");
        mode.set(1);
        assertThatThrownBy(() -> introspector.introspect("x")).isInstanceOf(IntrospectionException.class);
        assertThatThrownBy(() -> introspector.introspect("y")).isInstanceOf(IntrospectionException.class);
        assertThat(introspector.introspect("cached").active()).isTrue();
    }

    @Test
    void instantConversion() {
        Instant now = Instant.ofEpochSecond(1_800_000_000L);
        assertThat(CachingTokenIntrospector.instant(now)).isEqualTo(now);
        assertThat(CachingTokenIntrospector.instant(Date.from(now))).isEqualTo(now);
        assertThat(CachingTokenIntrospector.instant(1_800_000_000L)).isEqualTo(now);
        assertThat(CachingTokenIntrospector.instant(" 1800000000 ")).isEqualTo(now);
        assertThat(CachingTokenIntrospector.instant("soon")).isNull();
        assertThat(CachingTokenIntrospector.instant("")).isNull();
        assertThat(CachingTokenIntrospector.instant(null)).isNull();
        assertThat(CachingTokenIntrospector.hash("a")).hasSize(64).isNotEqualTo("a");
    }

    @Test
    void nullObservationsAreANoOp() {
        CachingTokenIntrospector introspector = new CachingTokenIntrospector(
                token -> IntrospectionResult.inactive(), Duration.ofSeconds(1), Duration.ZERO, 10,
                new IntrospectionCircuitBreaker(1, Duration.ofSeconds(1), clock), clock, null);
        introspector.introspect("a");
        assertThat(introspector.cachedResults()).isZero();
    }
}
