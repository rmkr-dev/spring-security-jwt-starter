package io.github.rmkrdev.entra.security.core.graph;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

import io.github.rmkrdev.entra.security.core.cache.TtlCache;

/**
 * Caches the result of another {@link GroupMembershipResolver} per tenant and user.
 */
public final class CachingGroupMembershipResolver implements GroupMembershipResolver {

    private final GroupMembershipResolver delegate;
    private final TtlCache<String, List<GroupMembership>> cache;

    public CachingGroupMembershipResolver(GroupMembershipResolver delegate, Duration ttl, int maxEntries) {
        this(delegate, ttl, maxEntries, Clock.systemUTC());
    }

    public CachingGroupMembershipResolver(GroupMembershipResolver delegate, Duration ttl, int maxEntries,
            Clock clock) {
        this(delegate, ttl, maxEntries, clock, false);
    }

    /**
     * @param bounded when {@code true}, membership lookups for one user share a single Graph call and the cache
     *                stays within {@code maxEntries}
     */
    public CachingGroupMembershipResolver(GroupMembershipResolver delegate, Duration ttl, int maxEntries,
            Clock clock, boolean bounded) {
        this.delegate = delegate;
        this.cache = new TtlCache<>(ttl, maxEntries, clock, bounded);
    }

    @Override
    public List<GroupMembership> resolve(String tenantId, String objectId) {
        return cache.get(tenantId + "|" + objectId, key -> List.copyOf(delegate.resolve(tenantId, objectId)));
    }
}
