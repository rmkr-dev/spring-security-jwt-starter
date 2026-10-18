package io.github.rmkrdev.entra.security.core.graph;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

import io.github.rmkrdev.entra.security.core.cache.TtlCache;
import reactor.core.publisher.Mono;

/**
 * Caches the result of another {@link ReactiveGroupMembershipResolver} per tenant and user. Failed lookups
 * are not cached.
 */
public final class CachingReactiveGroupMembershipResolver implements ReactiveGroupMembershipResolver {

    private final ReactiveGroupMembershipResolver delegate;
    private final TtlCache<String, List<GroupMembership>> cache;

    public CachingReactiveGroupMembershipResolver(ReactiveGroupMembershipResolver delegate, Duration ttl,
            int maxEntries) {
        this(delegate, ttl, maxEntries, Clock.systemUTC());
    }

    public CachingReactiveGroupMembershipResolver(ReactiveGroupMembershipResolver delegate, Duration ttl,
            int maxEntries, Clock clock) {
        this.delegate = delegate;
        this.cache = new TtlCache<>(ttl, maxEntries, clock);
    }

    @Override
    public Mono<List<GroupMembership>> resolve(String tenantId, String objectId) {
        String key = tenantId + "|" + objectId;
        return Mono.defer(() -> {
            List<GroupMembership> cached = cache.getIfPresent(key);
            if (cached != null) {
                return Mono.just(cached);
            }
            return delegate.resolve(tenantId, objectId)
                    .map(List::copyOf)
                    .doOnNext(groups -> cache.put(key, groups));
        });
    }
}
