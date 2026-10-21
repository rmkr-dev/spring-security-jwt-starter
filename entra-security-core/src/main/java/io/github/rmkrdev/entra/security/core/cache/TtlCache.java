package io.github.rmkrdev.entra.security.core.cache;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * A small thread-safe cache with a fixed time-to-live and an upper bound on entries.
 * <p>
 * {@code null} results and exceptions from the loader are not cached.
 * <p>
 * {@code bounded} is off by default. When it is on, {@link #put} never grows the map past {@code maxEntries}
 * even if several threads insert at once, and {@link #get} / {@link #coalesce} run one load per key.
 */
public final class TtlCache<K, V> {

    private final Map<K, Entry<V>> entries = new ConcurrentHashMap<>();
    private final Map<K, CompletableFuture<Object>> inflight = new ConcurrentHashMap<>();
    private final Object lock = new Object();
    private final Duration ttl;
    private final int maxEntries;
    private final Clock clock;
    private final boolean bounded;

    public TtlCache(Duration ttl, int maxEntries, Clock clock) {
        this(ttl, maxEntries, clock, false);
    }

    /**
     * @param bounded when {@code true}, the map stays within {@code maxEntries} under concurrency and loads of
     *                the same key are coalesced
     */
    public TtlCache(Duration ttl, int maxEntries, Clock clock, boolean bounded) {
        if (ttl == null || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be zero or positive");
        }
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be at least 1");
        }
        this.ttl = ttl;
        this.maxEntries = maxEntries;
        this.clock = clock;
        this.bounded = bounded;
    }

    /** Whether inserts are strictly capped and loads of one key are shared. */
    public boolean isBounded() {
        return bounded;
    }

    public V get(K key, Function<? super K, ? extends V> loader) {
        V cached = getIfPresent(key);
        if (cached != null) {
            return cached;
        }
        if (!bounded) {
            V value = loader.apply(key);
            put(key, value);
            return value;
        }
        return coalesce(key, () -> {
            V again = getIfPresent(key);
            if (again != null) {
                return again;
            }
            V value = loader.apply(key);
            put(key, value);
            return value;
        });
    }

    /**
     * Runs {@code load} once per key while {@code bounded} is on. The result is not stored; the caller stores it
     * with {@link #put} when it should be remembered. Failures are not remembered, so the next caller tries again.
     * When {@code bounded} is off, {@code load} runs on the caller.
     */
    public <T> T coalesce(K key, Supplier<T> load) {
        if (!bounded) {
            return load.get();
        }
        CompletableFuture<Object> created = new CompletableFuture<>();
        CompletableFuture<Object> current = inflight.putIfAbsent(key, created);
        if (current != null) {
            return await(current);
        }
        try {
            T value = load.get();
            created.complete(value);
            return value;
        }
        catch (Throwable ex) {
            created.completeExceptionally(ex);
            throw rethrow(ex);
        }
        finally {
            inflight.remove(key, created);
        }
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
        put(key, value, ttl);
    }

    /**
     * Stores {@code value} for {@code entryTtl}, capped at the configured time-to-live. {@code null} values and
     * zero or negative durations are ignored.
     */
    public void put(K key, V value, Duration entryTtl) {
        if (value == null || entryTtl == null || entryTtl.isZero() || entryTtl.isNegative() || ttl.isZero()) {
            return;
        }
        Duration effective = entryTtl.compareTo(ttl) > 0 ? ttl : entryTtl;
        if (!bounded) {
            Instant now = clock.instant();
            if (entries.size() >= maxEntries) {
                evict(now);
            }
            entries.put(key, new Entry<>(value, now.plus(effective)));
            return;
        }
        synchronized (lock) {
            Instant now = clock.instant();
            entries.values().removeIf(entry -> !entry.expiresAt().isAfter(now));
            if (!entries.containsKey(key)) {
                Iterator<K> keys = entries.keySet().iterator();
                while (entries.size() >= maxEntries && keys.hasNext()) {
                    keys.next();
                    keys.remove();
                }
            }
            entries.put(key, new Entry<>(value, now.plus(effective)));
        }
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

    @SuppressWarnings("unchecked")
    private <T> T await(CompletableFuture<Object> future) {
        try {
            return (T) future.join();
        }
        catch (CompletionException ex) {
            throw rethrow(ex.getCause() == null ? ex : ex.getCause());
        }
    }

    private RuntimeException rethrow(Throwable ex) {
        if (ex instanceof RuntimeException runtime) {
            return runtime;
        }
        if (ex instanceof Error error) {
            throw error;
        }
        return new IllegalStateException(ex);
    }

    private record Entry<V>(V value, Instant expiresAt) {
    }
}
