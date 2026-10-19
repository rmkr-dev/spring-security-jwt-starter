package io.github.rmkrdev.entra.security.core.cache;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

class TtlCacheTest {

    @Test
    void cachesUntilTtlAndBoundsSize() {
        MutableClock clock = new MutableClock();
        TtlCache<String, String> cache = new TtlCache<>(Duration.ofMinutes(1), 2, clock);
        AtomicInteger loads = new AtomicInteger();
        cache.get("a", k -> k + loads.incrementAndGet());
        cache.get("a", k -> k + loads.incrementAndGet());
        assertThat(loads).hasValue(1);
        clock.advance(Duration.ofMinutes(2));
        assertThat(cache.get("a", k -> k + loads.incrementAndGet())).isEqualTo("a2");
        cache.get("b", k -> k);
        cache.get("c", k -> k);
        assertThat(cache.size()).isLessThanOrEqualTo(2);
        assertThat(cache.get("n", k -> null)).isNull();
        assertThat(cache.size()).isLessThanOrEqualTo(2);
    }

    @Test
    void perEntryTtlIsCappedAtTheCacheTtl() {
        MutableClock clock = new MutableClock();
        TtlCache<String, String> cache = new TtlCache<>(Duration.ofMinutes(1), 10, clock);
        cache.put("short", "s", Duration.ofSeconds(10));
        cache.put("long", "l", Duration.ofHours(1));
        cache.put("zero", "z", Duration.ZERO);
        cache.put("negative", "n", Duration.ofSeconds(-1));
        cache.put("none", "x", null);
        assertThat(cache.size()).isEqualTo(2);
        clock.advance(Duration.ofSeconds(11));
        assertThat(cache.getIfPresent("short")).isNull();
        assertThat(cache.getIfPresent("long")).isEqualTo("l");
        clock.advance(Duration.ofMinutes(1));
        assertThat(cache.getIfPresent("long")).isNull();
    }

    static final class MutableClock extends Clock {

        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
