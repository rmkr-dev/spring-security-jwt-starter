package io.github.rmkrdev.entra.security.core.jwt;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.graph.GroupMembership;
import io.github.rmkrdev.entra.security.core.graph.GroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

/**
 * Converts a validated Entra {@link Jwt} into an {@link EntraAuthenticationToken} carrying an
 * {@link EntraPrincipal} and the mapped authorities.
 */
public final class EntraJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final Logger log = LoggerFactory.getLogger(EntraJwtAuthenticationConverter.class);

    private final EntraTokenClassifier classifier;
    private final EntraAuthorityMapper mapper;
    private final GroupMembershipResolver groupResolver;
    private final boolean requireKnownClient;
    private final SafeClaimLogger claimLogger;
    private final AtomicBoolean overageWarningLogged = new AtomicBoolean();

    /**
     * @param classifier         user/service classification
     * @param mapper             authority mapping
     * @param groupResolver      Graph lookup for group overage, or {@code null} to disable it
     * @param requireKnownClient reject service tokens whose client id is not in the client allow-list
     * @param claimLogger        safe DEBUG logging
     */
    public EntraJwtAuthenticationConverter(EntraTokenClassifier classifier, EntraAuthorityMapper mapper,
            GroupMembershipResolver groupResolver, boolean requireKnownClient, SafeClaimLogger claimLogger) {
        this.classifier = classifier;
        this.mapper = mapper;
        this.groupResolver = groupResolver;
        this.requireKnownClient = requireKnownClient;
        this.claimLogger = claimLogger;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        PrincipalType type = classifier.classify(jwt);
        String appId = EntraClaims.appId(jwt);
        if (type == PrincipalType.SERVICE && requireKnownClient && !mapper.isKnownClient(appId)) {
            throw new InvalidBearerTokenException("The calling client application is not allowed to call this API");
        }

        String tenantId = jwt.getClaimAsString(EntraClaimNames.TENANT_ID);
        String objectId = jwt.getClaimAsString(EntraClaimNames.OBJECT_ID);

        Set<String> groups = new LinkedHashSet<>(EntraClaims.stringList(jwt, EntraClaimNames.GROUPS));
        Set<String> groupKeys = new LinkedHashSet<>(groups);
        if (type == PrincipalType.USER && EntraClaims.isGroupOverage(jwt)) {
            resolveOverage(tenantId, objectId, groups, groupKeys);
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

    private void resolveOverage(String tenantId, String objectId, Set<String> groups, Set<String> groupKeys) {
        if (groupResolver == null) {
            if (overageWarningLogged.compareAndSet(false, true)) {
                log.warn("Entra group overage detected but entra.security.graph.overage-enabled is false; "
                        + "group-based roles will not be granted for users in too many groups");
            }
            return;
        }
        if (objectId == null) {
            log.warn("Entra group overage detected but the token has no oid claim; skipping Graph lookup");
            return;
        }
        try {
            for (GroupMembership membership : groupResolver.resolve(tenantId, objectId)) {
                groups.add(membership.id());
                groupKeys.add(membership.id());
                if (membership.displayName() != null) {
                    groupKeys.add(membership.displayName());
                }
            }
        }
        catch (RuntimeException ex) {
            log.warn("Microsoft Graph group lookup failed; continuing without group-based roles: {}",
                    ex.getMessage());
        }
    }
}
