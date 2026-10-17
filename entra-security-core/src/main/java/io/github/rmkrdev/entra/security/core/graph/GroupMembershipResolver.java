package io.github.rmkrdev.entra.security.core.graph;

import java.util.List;

/**
 * Resolves a user's (transitive) group memberships when the token omitted them (group overage).
 */
@FunctionalInterface
public interface GroupMembershipResolver {

    /**
     * @param tenantId the {@code tid} of the token
     * @param objectId the user's {@code oid}
     * @return the user's groups, never {@code null}
     */
    List<GroupMembership> resolve(String tenantId, String objectId);
}
