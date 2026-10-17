package io.github.rmkrdev.entra.security.core.principal;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.security.core.AuthenticatedPrincipal;

/**
 * The authenticated caller, derived from a validated Entra access token.
 * <p>
 * Inject it into controller methods as a plain parameter ({@code EntraPrincipal principal}),
 * with {@code @AuthenticationPrincipal}, or look it up with {@link EntraPrincipals#current()}.
 *
 * @param type          whether the caller is a user or a service (app-only token)
 * @param tenantId      the {@code tid} claim
 * @param objectId      the {@code oid} claim: the user or service principal object id
 * @param subject       the {@code sub} claim
 * @param appId         the calling client application id ({@code azp} for v2, {@code appid} for v1 tokens)
 * @param displayName   the {@code name} claim, if present
 * @param username      {@code preferred_username}, {@code upn} or {@code unique_name}, if present
 * @param roles         the granted Spring Security role authorities (for example {@code ROLE_ORDERS_READ})
 * @param appRoles      the raw {@code roles} claim values
 * @param groups        the group ids (or names) from the token, or resolved through Microsoft Graph on overage
 * @param scopes        the delegated scopes from the {@code scp} claim
 * @param tokenVersion  the {@code ver} claim ({@code 1.0} or {@code 2.0})
 */
public record EntraPrincipal(
        PrincipalType type,
        String tenantId,
        String objectId,
        String subject,
        String appId,
        String displayName,
        String username,
        Set<String> roles,
        Set<String> appRoles,
        Set<String> groups,
        Set<String> scopes,
        String tokenVersion) implements AuthenticatedPrincipal, Serializable {

    private static final long serialVersionUID = 1L;

    public EntraPrincipal {
        roles = copy(roles);
        appRoles = copy(appRoles);
        groups = copy(groups);
        scopes = copy(scopes);
    }

    /**
     * The stable identifier of the caller: the object id when present, otherwise the subject.
     */
    @Override
    public String getName() {
        return objectId != null ? objectId : subject;
    }

    public boolean isUser() {
        return type == PrincipalType.USER;
    }

    public boolean isService() {
        return type == PrincipalType.SERVICE;
    }

    /**
     * Whether a role was granted. Accepts {@code ORDERS_READ} or {@code ROLE_ORDERS_READ}.
     */
    public boolean hasRole(String role) {
        if (role == null) {
            return false;
        }
        String authority = role.startsWith("ROLE_") ? role : "ROLE_" + role;
        return roles.contains(authority);
    }

    /**
     * Whether the raw {@code roles} claim contains the given app role value.
     */
    public boolean hasAppRole(String appRole) {
        return appRoles.contains(appRole);
    }

    /**
     * Whether the caller is a member of the given group (id or name, case-insensitive).
     */
    public boolean isMemberOf(String group) {
        return group != null && groups.stream().anyMatch(group::equalsIgnoreCase);
    }

    private static Set<String> copy(Collection<String> values) {
        if (values == null || values.isEmpty()) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(values));
    }
}
