package io.github.rmkrdev.entra.security.core.graph;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import io.github.rmkrdev.entra.security.core.cache.TtlCache;
import reactor.core.publisher.Mono;

/**
 * Caches the result of another {@link ReactiveGroupMembershipResolver} per tenant and user. Failed lookups
 * are not cached.
 */
public final class CachingReactiveGroupMembershipResolver implements ReactiveGroupMembershipResolver {

    private final ReactiveGroupMembershipResolver delegate;
    private final TtlCache<String, List<GroupMembership>> cache;
    private final ConcurrentHashMap<String, Mono<List<GroupMembership>>> inflight = new ConcurrentHashMap<>();

    public CachingReactiveGroupMembershipResolver(ReactiveGroupMembershipResolver delegate, Duration ttl,
            int maxEntries) {
        this(delegate, ttl, maxEntries, Clock.systemUTC());
    }

    public CachingReactiveGroupMembershipResolver(ReactiveGroupMembershipResolver delegate, Duration ttl,
            int maxEntries, Clock clock) {
        this(delegate, ttl, maxEntries, clock, false);
    }

    /**
     * @param bounded when {@code true}, one Graph lookup runs per user and the cache stays within
     *                {@code maxEntries}
     */
    public CachingReactiveGroupMembershipResolver(ReactiveGroupMembershipResolver delegate, Duration ttl,
            int maxEntries, Clock clock, boolean bounded) {
        this.delegate = delegate;
        this.cache = new TtlCache<>(ttl, maxEntries, clock, bounded);
    }

    @Override
    public Mono<List<GroupMembership>> resolve(String tenantId, String objectId) {
        String key = tenantId + "|" + objectId;
        return Mono.defer(() -> {
            List<GroupMembership> cached = cache.getIfPresent(key);
            if (cached != null) {
                return Mono.just(cached);
            }
            if (!cache.isBounded()) {
                return load(key);
            }
            return inflight.computeIfAbsent(key, ignored -> load(key).doFinally(signal -> inflight.remove(key)).cache());
        });
    }

    private Mono<List<GroupMembership>> load(String key) {
        int split = key.indexOf('|');
        String tenantId = key.substring(0, split);
        String objectId = key.substring(split + 1);
        return delegate.resolve(tenantId, objectId)
                .map(List::copyOf)
                .doOnNext(groups -> cache.put(key, groups));
    }
}
