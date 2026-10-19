package io.github.rmkrdev.entra.security.core.jwt;

import java.util.List;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.graph.GroupMembership;
import io.github.rmkrdev.entra.security.core.graph.GroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

/**
 * Converts a validated Entra {@link Jwt} into an {@link EntraAuthenticationToken} carrying an
 * {@link EntraPrincipal} and the mapped authorities.
 */
public final class EntraJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final EntraAuthenticationAssembler assembler;
    private final GroupMembershipResolver groupResolver;
    private final EntraSecurityObservations observations;
    private final AuthenticationCache cache;

    /**
     * @param classifier         user/service classification
     * @param mapper             authority mapping
     * @param groupResolver      Graph lookup for group overage, or {@code null} to disable it
     * @param requireKnownClient reject service tokens whose client id is not in the client allow-list
     * @param claimLogger        safe DEBUG logging
     */
    public EntraJwtAuthenticationConverter(EntraTokenClassifier classifier, EntraAuthorityMapper mapper,
            GroupMembershipResolver groupResolver, boolean requireKnownClient, SafeClaimLogger claimLogger) {
        this(classifier, mapper, groupResolver, requireKnownClient, claimLogger, EntraSecurityObservations.NO_OP);
    }

    /**
     * @param observations authentication outcomes; {@code null} is treated as
     *                     {@link EntraSecurityObservations#NO_OP}
     */
    public EntraJwtAuthenticationConverter(EntraTokenClassifier classifier, EntraAuthorityMapper mapper,
            GroupMembershipResolver groupResolver, boolean requireKnownClient, SafeClaimLogger claimLogger,
            EntraSecurityObservations observations) {
        this(new EntraAuthenticationAssembler(classifier, mapper, requireKnownClient, claimLogger), groupResolver,
                observations, null);
    }

    private EntraJwtAuthenticationConverter(EntraAuthenticationAssembler assembler,
            GroupMembershipResolver groupResolver, EntraSecurityObservations observations, AuthenticationCache cache) {
        this.assembler = assembler;
        this.groupResolver = groupResolver;
        this.observations = observations == null ? EntraSecurityObservations.NO_OP : observations;
        this.cache = cache;
    }

    /**
     * The same converter, remembering the mapped principal and authorities per token in {@code cache}.
     */
    public EntraJwtAuthenticationConverter withCache(AuthenticationCache cache) {
        return new EntraJwtAuthenticationConverter(assembler, groupResolver, observations, cache);
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        if (observations == EntraSecurityObservations.NO_OP) {
            return doConvert(jwt);
        }
        try {
            AbstractAuthenticationToken authentication = doConvert(jwt);
            observations.jwtAuthentication(true, JwtAuthenticationOutcomes.NONE);
            return authentication;
        }
        catch (RuntimeException ex) {
            observations.jwtAuthentication(false, JwtAuthenticationOutcomes.reason(ex));
            throw ex;
        }
    }

    private AbstractAuthenticationToken doConvert(Jwt jwt) {
        if (cache != null) {
            EntraAuthenticationToken cached = cache.get(jwt);
            if (cached != null) {
                return cached;
            }
        }
        PrincipalType type = assembler.classify(jwt);
        List<GroupMembership> resolved = List.of();
        boolean complete = true;
        if (assembler.shouldResolveOverage(jwt, type, groupResolver != null)) {
            try {
                resolved = groupResolver.resolve(jwt.getClaimAsString(EntraClaimNames.TENANT_ID),
                        jwt.getClaimAsString(EntraClaimNames.OBJECT_ID));
            }
            catch (RuntimeException ex) {
                assembler.groupLookupFailed(ex);
                complete = false;
            }
        }
        EntraAuthenticationToken authentication = assembler.assemble(jwt, type, resolved);
        if (cache != null && complete) {
            cache.put(jwt, authentication);
        }
        return authentication;
    }
}
