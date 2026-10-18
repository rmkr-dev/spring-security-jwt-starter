package io.github.rmkrdev.entra.security.core.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.graph.GroupMembership;
import io.github.rmkrdev.entra.security.core.graph.GroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.graph.ReactiveGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class ReactiveEntraJwtAuthenticationConverterTest {

    private final EntraAuthorityMapper mapper = EntraAuthorityMapper.builder()
            .groupRoleMappings(Map.of("g-1", List.of("READER"), "Big Group", List.of("BIG")))
            .clientRoleMappings(Map.of("peer", List.of("PEER")))
            .build();

    @Test
    void producesTheSamePrincipalAsTheServletConverter() {
        Jwt jwt = EntraTokenClassifierTest.jwt(Map.of("scp", "access_as_user", "oid", "o-1", "tid", "t-1",
                "groups", List.of("g-1"), "roles", List.of("Writer"), "azp", "spa", "name", "Jane", "ver", "2.0"));
        EntraJwtAuthenticationConverter servlet = new EntraJwtAuthenticationConverter(new EntraTokenClassifier(),
                mapper, null, false, new SafeClaimLogger(false));

        EntraAuthenticationToken reactive = (EntraAuthenticationToken) converter(null, false).convert(jwt).block();
        EntraAuthenticationToken blocking = (EntraAuthenticationToken) servlet.convert(jwt);

        assertThat(reactive.getEntraPrincipal()).isEqualTo(blocking.getEntraPrincipal());
        assertThat(reactive.getAuthorities()).isEqualTo(blocking.getAuthorities());
        assertThat(reactive.getEntraPrincipal().type()).isEqualTo(PrincipalType.USER);
        assertThat(reactive.getAuthorities()).extracting("authority")
                .containsExactlyInAnyOrder("ROLE_READER", "ROLE_Writer");
    }

    @Test
    void overageIsResolvedReactivelyWithIdsAndNames() {
        AtomicInteger calls = new AtomicInteger();
        ReactiveGroupMembershipResolver resolver = (tid, oid) -> Mono.fromSupplier(() -> {
            calls.incrementAndGet();
            assertThat(tid).isEqualTo("t");
            assertThat(oid).isEqualTo("o-1");
            return List.of(new GroupMembership("g-9", "Big Group"));
        });
        Jwt jwt = EntraTokenClassifierTest.jwt(Map.of("scp", "s", "oid", "o-1", "tid", "t",
                "_claim_names", Map.of("groups", "src1")));

        Mono<AbstractAuthenticationToken> result = converter(resolver, false).convert(jwt);
        assertThat(calls).hasValue(0);
        EntraPrincipal principal = (EntraPrincipal) result.block().getPrincipal();

        assertThat(principal.roles()).containsExactly("ROLE_BIG");
        assertThat(principal.groups()).containsExactly("g-9");
        assertThat(calls).hasValue(1);
    }

    @Test
    void blockingResolverCanBeAdapted() {
        GroupMembershipResolver blocking = (tid, oid) -> List.of(new GroupMembership("g-1", null));
        Jwt jwt = EntraTokenClassifierTest.jwt(Map.of("scp", "s", "oid", "o-1", "hasgroups", true));
        EntraPrincipal principal = (EntraPrincipal) converter(ReactiveGroupMembershipResolver.fromBlocking(blocking),
                false).convert(jwt).block().getPrincipal();
        assertThat(principal.roles()).containsExactly("ROLE_READER");
    }

    @Test
    void resolverErrorFailsClosedWithoutFailingTheRequest() {
        ReactiveGroupMembershipResolver failing = (tid, oid) -> Mono.error(new IllegalStateException("graph down"));
        Jwt jwt = EntraTokenClassifierTest.jwt(Map.of("scp", "s", "oid", "o-1", "hasgroups", true));
        StepVerifier.create(converter(failing, false).convert(jwt))
                .assertNext(auth -> assertThat(((EntraPrincipal) auth.getPrincipal()).roles()).isEmpty())
                .verifyComplete();

        ReactiveGroupMembershipResolver throwing = (tid, oid) -> {
            throw new IllegalStateException("broken");
        };
        StepVerifier.create(converter(throwing, false).convert(jwt))
                .assertNext(auth -> assertThat(((EntraPrincipal) auth.getPrincipal()).roles()).isEmpty())
                .verifyComplete();
    }

    @Test
    void overageWithoutResolverOrOidSkipsTheLookup() {
        AtomicInteger calls = new AtomicInteger();
        ReactiveGroupMembershipResolver counting = (tid, oid) -> {
            calls.incrementAndGet();
            return Mono.just(List.of());
        };
        Jwt noOid = EntraTokenClassifierTest.jwt(Map.of("scp", "s", "hasgroups", true));
        assertThat(((EntraPrincipal) converter(counting, false).convert(noOid).block().getPrincipal()).roles())
                .isEmpty();
        Jwt overage = EntraTokenClassifierTest.jwt(Map.of("scp", "s", "oid", "o-1", "hasgroups", true));
        assertThat(((EntraPrincipal) converter(null, false).convert(overage).block().getPrincipal()).roles())
                .isEmpty();
        Jwt service = EntraTokenClassifierTest.jwt(Map.of("idtyp", "app", "oid", "o-1", "hasgroups", true));
        converter(counting, false).convert(service).block();
        assertThat(calls).hasValue(0);
    }

    @Test
    void unknownServiceClientIsAnErrorSignal() {
        ReactiveEntraJwtAuthenticationConverter converter = converter(null, true);
        StepVerifier.create(converter.convert(EntraTokenClassifierTest.jwt(Map.of("idtyp", "app", "azp", "stranger"))))
                .expectError(InvalidBearerTokenException.class)
                .verify();
        EntraPrincipal peer = (EntraPrincipal) converter.convert(EntraTokenClassifierTest.jwt(Map.of("idtyp", "app",
                "appid", "peer", "roles", List.of("Sync")))).block().getPrincipal();
        assertThat(peer.isService()).isTrue();
        assertThat(peer.roles()).containsExactlyInAnyOrder("ROLE_PEER", "ROLE_Sync");
    }

    @Test
    void outcomesAreObserved() {
        List<String> outcomes = new ArrayList<>();
        ReactiveEntraJwtAuthenticationConverter converter = new ReactiveEntraJwtAuthenticationConverter(
                new EntraTokenClassifier(), mapper, null, true, new SafeClaimLogger(false),
                new EntraSecurityObservations() {
                    @Override
                    public void jwtAuthentication(boolean success, String reason) {
                        outcomes.add(success + ":" + reason);
                    }
                });
        converter.convert(EntraTokenClassifierTest.jwt(Map.of("idtyp", "app", "azp", "peer"))).block();
        StepVerifier.create(converter.convert(EntraTokenClassifierTest.jwt(Map.of("idtyp", "app", "azp", "x"))))
                .expectError(InvalidBearerTokenException.class)
                .verify();
        assertThat(outcomes).containsExactly("true:none", "false:client_not_allowed");
    }

    private ReactiveEntraJwtAuthenticationConverter converter(ReactiveGroupMembershipResolver resolver,
            boolean requireKnownClient) {
        return new ReactiveEntraJwtAuthenticationConverter(new EntraTokenClassifier(), mapper, resolver,
                requireKnownClient, new SafeClaimLogger(false), EntraSecurityObservations.NO_OP);
    }
}
