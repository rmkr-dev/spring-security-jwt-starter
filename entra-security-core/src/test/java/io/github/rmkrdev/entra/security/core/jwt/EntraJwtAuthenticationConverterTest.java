package io.github.rmkrdev.entra.security.core.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.graph.GroupMembership;
import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

class EntraJwtAuthenticationConverterTest {

    private final EntraAuthorityMapper mapper = EntraAuthorityMapper.builder()
            .groupRoleMappings(Map.of("g-1", List.of("READER"), "Big Group", List.of("BIG")))
            .clientRoleMappings(Map.of("peer", List.of("PEER")))
            .build();

    @Test
    void userPrincipal() {
        EntraJwtAuthenticationConverter converter = new EntraJwtAuthenticationConverter(new EntraTokenClassifier(),
                mapper, null, false, new SafeClaimLogger(true));
        Jwt jwt = EntraTokenClassifierTest.jwt(Map.of("scp", "access_as_user", "oid", "o-1", "tid", "t-1",
                "groups", List.of("g-1"), "azp", "spa", "name", "Jane", "ver", "2.0"));
        EntraAuthenticationToken auth = (EntraAuthenticationToken) converter.convert(jwt);
        EntraPrincipal principal = auth.getEntraPrincipal();
        assertThat(principal.type()).isEqualTo(PrincipalType.USER);
        assertThat(principal.getName()).isEqualTo("o-1");
        assertThat(auth.getName()).isEqualTo("o-1");
        assertThat(principal.hasRole("READER")).isTrue();
        assertThat(principal.isMemberOf("G-1")).isTrue();
        assertThat(auth.getAuthorities()).extracting("authority").containsExactly("ROLE_READER");
        assertThat(auth.getTokenAttributes()).containsEntry("oid", "o-1");
    }

    @Test
    void overageUsesResolverWithIdsAndNames() {
        AtomicInteger calls = new AtomicInteger();
        EntraJwtAuthenticationConverter converter = new EntraJwtAuthenticationConverter(new EntraTokenClassifier(),
                mapper, (tid, oid) -> {
                    calls.incrementAndGet();
                    return List.of(new GroupMembership("g-9", "Big Group"));
                }, false, new SafeClaimLogger(false));
        Jwt jwt = EntraTokenClassifierTest.jwt(Map.of("scp", "s", "oid", "o-1", "tid", "t",
                "_claim_names", Map.of("groups", "src1")));
        EntraPrincipal principal = (EntraPrincipal) converter.convert(jwt).getPrincipal();
        assertThat(principal.roles()).containsExactly("ROLE_BIG");
        assertThat(principal.groups()).containsExactly("g-9");
        assertThat(calls).hasValue(1);
    }

    @Test
    void overageResolverFailureFailsClosed() {
        EntraJwtAuthenticationConverter converter = new EntraJwtAuthenticationConverter(new EntraTokenClassifier(),
                mapper, (tid, oid) -> {
                    throw new IllegalStateException("graph down");
                }, false, new SafeClaimLogger(false));
        Jwt jwt = EntraTokenClassifierTest.jwt(Map.of("scp", "s", "oid", "o-1", "hasgroups", true));
        assertThat(((EntraPrincipal) converter.convert(jwt).getPrincipal()).roles()).isEmpty();
    }

    @Test
    void unknownServiceClientRejectedWhenAllowListRequired() {
        EntraJwtAuthenticationConverter converter = new EntraJwtAuthenticationConverter(new EntraTokenClassifier(),
                mapper, null, true, new SafeClaimLogger(false));
        assertThatThrownBy(() -> converter.convert(EntraTokenClassifierTest.jwt(Map.of("idtyp", "app",
                "azp", "stranger")))).isInstanceOf(InvalidBearerTokenException.class);
        EntraPrincipal peer = (EntraPrincipal) converter.convert(EntraTokenClassifierTest.jwt(Map.of("idtyp", "app",
                "appid", "peer", "roles", List.of("Sync")))).getPrincipal();
        assertThat(peer.isService()).isTrue();
        assertThat(peer.roles()).containsExactlyInAnyOrder("ROLE_PEER", "ROLE_Sync");
    }
}
