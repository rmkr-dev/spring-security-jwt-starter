package io.github.rmkrdev.entra.security.core.jwt;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.graph.GroupMembership;
import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

/**
 * The part of JWT conversion shared by {@link EntraJwtAuthenticationConverter} and
 * {@link ReactiveEntraJwtAuthenticationConverter}: classification, the client allow-list, the overage
 * decision and building the principal. Only the Graph lookup differs between the two.
 */
final class EntraAuthenticationAssembler {

    private static final Logger log = LoggerFactory.getLogger(EntraJwtAuthenticationConverter.class);

    private final EntraTokenClassifier classifier;
    private final EntraAuthorityMapper mapper;
    private final boolean requireKnownClient;
    private final SafeClaimLogger claimLogger;
    private final AtomicBoolean overageWarningLogged = new AtomicBoolean();

    EntraAuthenticationAssembler(EntraTokenClassifier classifier, EntraAuthorityMapper mapper,
            boolean requireKnownClient, SafeClaimLogger claimLogger) {
        this.classifier = classifier;
        this.mapper = mapper;
        this.requireKnownClient = requireKnownClient;
        this.claimLogger = claimLogger;
    }

    /**
     * Classifies the token and applies the client allow-list.
     *
     * @throws InvalidBearerTokenException when a service caller is not in the allow-list
     */
    PrincipalType classify(Jwt jwt) {
        PrincipalType type = classifier.classify(jwt);
        if (type == PrincipalType.SERVICE && requireKnownClient && !mapper.isKnownClient(EntraClaims.appId(jwt))) {
            throw new InvalidBearerTokenException("The calling client application is not allowed to call this API");
        }
        return type;
    }

    /**
     * Whether a Graph lookup should run for this token: a user token with the overage marker, a configured
     * resolver and an {@code oid}. Logs why when it should but cannot.
     */
    boolean shouldResolveOverage(Jwt jwt, PrincipalType type, boolean resolverAvailable) {
        if (type != PrincipalType.USER || !EntraClaims.isGroupOverage(jwt)) {
            return false;
        }
        if (!resolverAvailable) {
            if (overageWarningLogged.compareAndSet(false, true)) {
                log.warn("Entra group overage detected but entra.security.graph.overage-enabled is false; "
                        + "group-based roles will not be granted for users in too many groups");
            }
            return false;
        }
        if (jwt.getClaimAsString(EntraClaimNames.OBJECT_ID) == null) {
            log.warn("Entra group overage detected but the token has no oid claim; skipping Graph lookup");
            return false;
        }
        return true;
    }

    void groupLookupFailed(Throwable ex) {
        log.warn("Microsoft Graph group lookup failed; continuing without group-based roles: {}", ex.getMessage());
    }

    /**
     * Builds the authentication from the token and the groups resolved through Graph, if any.
     */
    EntraAuthenticationToken assemble(Jwt jwt, PrincipalType type, Collection<GroupMembership> resolvedGroups) {
        String appId = EntraClaims.appId(jwt);
        String tenantId = jwt.getClaimAsString(EntraClaimNames.TENANT_ID);
        String objectId = jwt.getClaimAsString(EntraClaimNames.OBJECT_ID);

        Set<String> groups = new LinkedHashSet<>(EntraClaims.stringList(jwt, EntraClaimNames.GROUPS));
        Set<String> groupKeys = new LinkedHashSet<>(groups);
        for (GroupMembership membership : resolvedGroups) {
            groups.add(membership.id());
            groupKeys.add(membership.id());
            if (membership.displayName() != null) {
                groupKeys.add(membership.displayName());
            }
        }

        List<String> appRoles = EntraClaims.stringList(jwt, EntraClaimNames.ROLES);
        List<String> scopes = EntraClaims.scopes(jwt);
        Set<String> authorityNames = mapper.map(type, groupKeys, appRoles, scopes, appId);

        EntraPrincipal principal = new EntraPrincipal(type, tenantId, objectId, jwt.getSubject(), appId,
                jwt.getClaimAsString(EntraClaimNames.NAME), EntraClaims.username(jwt), authorityNames,
                new LinkedHashSet<>(appRoles), groups, new LinkedHashSet<>(scopes),
                jwt.getClaimAsString(EntraClaimNames.VERSION));
        claimLogger.log(jwt, principal);

        List<GrantedAuthority> authorities = authorityNames.stream()
                .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                .toList();
        return new EntraAuthenticationToken(jwt, principal, authorities);
    }
}
