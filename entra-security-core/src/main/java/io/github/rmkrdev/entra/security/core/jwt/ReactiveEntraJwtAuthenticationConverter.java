package io.github.rmkrdev.entra.security.core.jwt;

import java.util.List;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.graph.GroupMembership;
import io.github.rmkrdev.entra.security.core.graph.ReactiveGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;
import reactor.core.publisher.Mono;

/**
 * Reactive counterpart of {@link EntraJwtAuthenticationConverter} for WebFlux resource servers. Classification,
 * the client allow-list and role mapping are identical; the group-overage lookup goes through a
 * {@link ReactiveGroupMembershipResolver} so it does not block the event loop.
 */
public final class ReactiveEntraJwtAuthenticationConverter
        implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

    private final EntraAuthenticationAssembler assembler;
    private final ReactiveGroupMembershipResolver groupResolver;
    private final EntraSecurityObservations observations;
    private final AuthenticationCache cache;

    /**
     * @param classifier         user/service classification
     * @param mapper             authority mapping
     * @param groupResolver      Graph lookup for group overage, or {@code null} to disable it
     * @param requireKnownClient reject service tokens whose client id is not in the client allow-list
     * @param claimLogger        safe DEBUG logging
     * @param observations       authentication outcomes; {@code null} is treated as
     *                           {@link EntraSecurityObservations#NO_OP}
     */
    public ReactiveEntraJwtAuthenticationConverter(EntraTokenClassifier classifier, EntraAuthorityMapper mapper,
            ReactiveGroupMembershipResolver groupResolver, boolean requireKnownClient, SafeClaimLogger claimLogger,
            EntraSecurityObservations observations) {
        this(new EntraAuthenticationAssembler(classifier, mapper, requireKnownClient, claimLogger), groupResolver,
                observations, null);
    }

    private ReactiveEntraJwtAuthenticationConverter(EntraAuthenticationAssembler assembler,
            ReactiveGroupMembershipResolver groupResolver, EntraSecurityObservations observations,
            AuthenticationCache cache) {
        this.assembler = assembler;
        this.groupResolver = groupResolver;
        this.observations = observations == null ? EntraSecurityObservations.NO_OP : observations;
        this.cache = cache;
    }

    /**
     * The same converter, remembering the mapped principal and authorities per token in {@code cache}.
     */
    public ReactiveEntraJwtAuthenticationConverter withCache(AuthenticationCache cache) {
        return new ReactiveEntraJwtAuthenticationConverter(assembler, groupResolver, observations, cache);
    }

    @Override
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        Mono<AbstractAuthenticationToken> authentication = Mono.defer(() -> doConvert(jwt))
                .map(AbstractAuthenticationToken.class::cast);
        if (observations == EntraSecurityObservations.NO_OP) {
            return authentication;
        }
        return authentication
                .doOnNext(token -> observations.jwtAuthentication(true, JwtAuthenticationOutcomes.NONE))
                .doOnError(ex -> observations.jwtAuthentication(false, JwtAuthenticationOutcomes.reason(ex)));
    }

    private Mono<EntraAuthenticationToken> doConvert(Jwt jwt) {
        if (cache != null) {
            EntraAuthenticationToken cached = cache.get(jwt);
            if (cached != null) {
                return Mono.just(cached);
            }
        }
        PrincipalType type = assembler.classify(jwt);
        if (!assembler.shouldResolveOverage(jwt, type, groupResolver != null)) {
            return Mono.just(remember(jwt, assembler.assemble(jwt, type, List.of())));
        }
        return Mono.defer(() -> groupResolver.resolve(jwt.getClaimAsString(EntraClaimNames.TENANT_ID),
                        jwt.getClaimAsString(EntraClaimNames.OBJECT_ID)))
                .defaultIfEmpty(List.of())
                .map(groups -> new Lookup(groups, true))
                .onErrorResume(RuntimeException.class, ex -> {
                    assembler.groupLookupFailed(ex);
                    return Mono.just(new Lookup(List.of(), false));
                })
                .map(lookup -> {
                    EntraAuthenticationToken authentication = assembler.assemble(jwt, type, lookup.groups());
                    return lookup.complete() ? remember(jwt, authentication) : authentication;
                });
    }

    private EntraAuthenticationToken remember(Jwt jwt, EntraAuthenticationToken authentication) {
        if (cache != null) {
            cache.put(jwt, authentication);
        }
        return authentication;
    }

    private record Lookup(List<GroupMembership> groups, boolean complete) {
    }
}
