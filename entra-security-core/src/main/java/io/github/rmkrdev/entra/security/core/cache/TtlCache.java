package io.github.rmkrdev.entra.security.core.cache;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * A small thread-safe cache with a fixed time-to-live and an upper bound on entries.
 * <p>
 * {@code null} results and exceptions from the loader are not cached.
 */
public final class TtlCache<K, V> {

    private final Map<K, Entry<V>> entries = new ConcurrentHashMap<>();
    private final Duration ttl;
    private final int maxEntries;
    private final Clock clock;

    public TtlCache(Duration ttl, int maxEntries, Clock clock) {
        if (ttl == null || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be zero or positive");
        }
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be at least 1");
        }
        this.ttl = ttl;
        this.maxEntries = maxEntries;
        this.clock = clock;
    }

    public V get(K key, Function<? super K, ? extends V> loader) {
        V cached = getIfPresent(key);
        if (cached != null) {
            return cached;
        }
        V value = loader.apply(key);
        put(key, value);
        return value;
    }

    /**
     * The live value for {@code key}, or {@code null} when absent or expired.
     */
    public V getIfPresent(K key) {
        Entry<V> existing = entries.get(key);
        if (existing != null && existing.expiresAt().isAfter(clock.instant())) {
            return existing.value();
        }
        return null;
    }

    /**
     * Stores {@code value} for the configured time-to-live. {@code null} values are ignored, and nothing is
     * stored when the time-to-live is zero.
     */
    public void put(K key, V value) {
        if (value == null || ttl.isZero()) {
            return;
        }
        Instant now = clock.instant();
        if (entries.size() >= maxEntries) {
            evict(now);
        }
        entries.put(key, new Entry<>(value, now.plus(ttl)));
    }

    public int size() {
        return entries.size();
    }

    public void invalidateAll() {
        entries.clear();
    }

    private void evict(Instant now) {
        entries.values().removeIf(entry -> !entry.expiresAt().isAfter(now));
        Iterator<K> keys = entries.keySet().iterator();
        while (entries.size() >= maxEntries && keys.hasNext()) {
            keys.next();
            keys.remove();
        }
    }

    private record Entry<V>(V value, Instant expiresAt) {
    }
}
