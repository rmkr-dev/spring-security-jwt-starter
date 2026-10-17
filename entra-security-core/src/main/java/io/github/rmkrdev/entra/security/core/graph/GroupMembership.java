package io.github.rmkrdev.entra.security.core.graph;

/**
 * A group the user belongs to, as returned by Microsoft Graph.
 *
 * @param id          the group object id
 * @param displayName the group display name, may be {@code null}
 */
public record GroupMembership(String id, String displayName) {
}
