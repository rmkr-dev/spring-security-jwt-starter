package io.github.rmkrdev.entra.security.core.authority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

/**
 * Turns Entra groups, app roles, scopes and client ids into Spring Security authorities.
 * <p>
 * Mapping keys (group ids or names, app role values, client ids) are matched case-insensitively.
 * Mapped role names are normalised to carry the {@code ROLE_} prefix, so {@code ORDERS_READ}
 * and {@code ROLE_ORDERS_READ} are equivalent in configuration.
 */
public final class EntraAuthorityMapper {

    public static final String ROLE_PREFIX = "ROLE_";
    public static final String SCOPE_PREFIX = "SCOPE_";

    private final Map<String, Set<String>> groupRoles;
    private final Map<String, Set<String>> appRoles;
    private final Map<String, Set<String>> clientRoles;
    private final boolean includeUserRolesClaim;
    private final boolean includeScopes;
    private final boolean mapUnmappedAppRoles;
    private final Set<String> defaultUserRoles;
    private final Set<String> defaultServiceRoles;

    private EntraAuthorityMapper(Builder builder) {
        this.groupRoles = normalise(builder.groupRoleMappings);
        this.appRoles = normalise(builder.appRoleMappings);
        this.clientRoles = normalise(builder.clientRoleMappings);
        this.includeUserRolesClaim = builder.includeUserRolesClaim;
        this.includeScopes = builder.includeScopes;
        this.mapUnmappedAppRoles = builder.mapUnmappedAppRoles;
        this.defaultUserRoles = toRoles(builder.defaultUserRoles);
        this.defaultServiceRoles = toRoles(builder.defaultServiceRoles);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Computes the authorities for a caller.
     *
     * @param type     user or service
     * @param groups   group ids and/or names from the token or from Microsoft Graph
     * @param appRoles values of the {@code roles} claim
     * @param scopes   values of the {@code scp} claim
     * @param appId    the calling client id ({@code azp}/{@code appid})
     * @return the authority names, sorted
     */
    public Set<String> map(PrincipalType type, Collection<String> groups, Collection<String> appRoles,
            Collection<String> scopes, String appId) {
        Set<String> authorities = new TreeSet<>();
        for (String group : safe(groups)) {
            authorities.addAll(lookup(groupRoles, group));
        }
        boolean service = type == PrincipalType.SERVICE;
        if (service || includeUserRolesClaim) {
            for (String appRole : safe(appRoles)) {
                Set<String> mapped = lookup(this.appRoles, appRole);
                if (!mapped.isEmpty()) {
                    authorities.addAll(mapped);
                }
                else if (mapUnmappedAppRoles) {
                    authorities.add(toRole(appRole));
                }
            }
        }
        if (service) {
            authorities.addAll(lookup(clientRoles, appId));
            authorities.addAll(defaultServiceRoles);
        }
        else {
            if (includeScopes) {
                for (String scope : safe(scopes)) {
                    authorities.add(SCOPE_PREFIX + scope);
                }
            }
            authorities.addAll(defaultUserRoles);
        }
        return authorities;
    }

    /**
     * Whether the client id appears in the client (azp/appid) allow-list.
     */
    public boolean isKnownClient(String appId) {
        return appId != null && clientRoles.containsKey(key(appId));
    }

    /**
     * Normalises a role name to carry the {@code ROLE_} prefix.
     */
    public static String toRole(String role) {
        String trimmed = role.trim();
        return trimmed.startsWith(ROLE_PREFIX) ? trimmed : ROLE_PREFIX + trimmed;
    }

    private static Set<String> lookup(Map<String, Set<String>> mappings, String value) {
        if (value == null) {
            return Collections.emptySet();
        }
        return mappings.getOrDefault(key(value), Collections.emptySet());
    }

    private static Map<String, Set<String>> normalise(Map<String, ? extends Collection<String>> source) {
        Map<String, Set<String>> result = new LinkedHashMap<>();
        if (source == null) {
            return result;
        }
        source.forEach((k, v) -> {
            if (k != null && !k.isBlank()) {
                result.computeIfAbsent(key(k), x -> new TreeSet<>()).addAll(toRoles(v));
            }
        });
        result.replaceAll((k, v) -> Collections.unmodifiableSet(v));
        return Collections.unmodifiableMap(result);
    }

    private static Set<String> toRoles(Collection<String> roles) {
        Set<String> result = new TreeSet<>();
        for (String role : safe(roles)) {
            if (role != null && !role.isBlank()) {
                result.add(toRole(role));
            }
        }
        return result;
    }

    private static String key(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private static Collection<String> safe(Collection<String> values) {
        return values == null ? Collections.emptyList() : values;
    }

    /**
     * Builder for {@link EntraAuthorityMapper}.
     */
    public static final class Builder {

        private Map<String, ? extends Collection<String>> groupRoleMappings = Map.of();
        private Map<String, ? extends Collection<String>> appRoleMappings = Map.of();
        private Map<String, ? extends Collection<String>> clientRoleMappings = Map.of();
        private boolean includeUserRolesClaim = true;
        private boolean includeScopes = false;
        private boolean mapUnmappedAppRoles = true;
        private List<String> defaultUserRoles = new ArrayList<>();
        private List<String> defaultServiceRoles = new ArrayList<>();

        private Builder() {
        }

        /** Group id or name → roles. */
        public Builder groupRoleMappings(Map<String, ? extends Collection<String>> mappings) {
            this.groupRoleMappings = mappings;
            return this;
        }

        /** App role value (the {@code roles} claim) → roles. */
        public Builder appRoleMappings(Map<String, ? extends Collection<String>> mappings) {
            this.appRoleMappings = mappings;
            return this;
        }

        /** Client id ({@code azp}/{@code appid}) → roles; also acts as the service allow-list. */
        public Builder clientRoleMappings(Map<String, ? extends Collection<String>> mappings) {
            this.clientRoleMappings = mappings;
            return this;
        }

        /** Whether the {@code roles} claim of user tokens (enterprise app assignments) is used. */
        public Builder includeUserRolesClaim(boolean include) {
            this.includeUserRolesClaim = include;
            return this;
        }

        /** Whether {@code scp} values become {@code SCOPE_x} authorities. */
        public Builder includeScopes(boolean include) {
            this.includeScopes = include;
            return this;
        }

        /** Whether app roles without an explicit mapping become {@code ROLE_<value>}. */
        public Builder mapUnmappedAppRoles(boolean map) {
            this.mapUnmappedAppRoles = map;
            return this;
        }

        public Builder defaultUserRoles(Collection<String> roles) {
            this.defaultUserRoles = new ArrayList<>(safe(roles));
            return this;
        }

        public Builder defaultServiceRoles(Collection<String> roles) {
            this.defaultServiceRoles = new ArrayList<>(safe(roles));
            return this;
        }

        public EntraAuthorityMapper build() {
            return new EntraAuthorityMapper(this);
        }
    }
}
