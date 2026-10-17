package io.github.rmkrdev.entra.security.core.authority;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

class EntraAuthorityMapperTest {

    private static final String READERS = "aaaaaaaa-0000-0000-0000-000000000001";

    private final EntraAuthorityMapper mapper = EntraAuthorityMapper.builder()
            .groupRoleMappings(Map.of(READERS, List.of("ORDERS_READ"), "Order Admins", List.of("ROLE_ORDERS_ADMIN")))
            .appRoleMappings(Map.of("Orders.Sync", List.of("SYNC")))
            .clientRoleMappings(Map.of("peer-app", List.of("PEER")))
            .includeScopes(true)
            .defaultUserRoles(List.of("USER"))
            .defaultServiceRoles(List.of("SERVICE"))
            .build();

    @Test
    void mapsGroupIdsCaseInsensitivelyAndNormalisesPrefix() {
        assertThat(mapper.map(PrincipalType.USER, List.of(READERS.toUpperCase()), List.of(), List.of(), null))
                .containsExactlyInAnyOrder("ROLE_ORDERS_READ", "ROLE_USER");
    }

    @Test
    void mapsGroupNames() {
        assertThat(mapper.map(PrincipalType.USER, List.of("order admins"), List.of(), List.of(), null))
                .contains("ROLE_ORDERS_ADMIN");
    }

    @Test
    void userRolesClaimAndScopes() {
        assertThat(mapper.map(PrincipalType.USER, List.of(), List.of("Orders.Sync", "Reports.View"),
                List.of("access_as_user"), "spa"))
                .containsExactlyInAnyOrder("ROLE_SYNC", "ROLE_Reports.View", "SCOPE_access_as_user", "ROLE_USER");
    }

    @Test
    void userRolesClaimCanBeIgnored() {
        EntraAuthorityMapper strict = EntraAuthorityMapper.builder().includeUserRolesClaim(false).build();
        assertThat(strict.map(PrincipalType.USER, List.of(), List.of("Admin"), List.of("x"), null)).isEmpty();
    }

    @Test
    void serviceAppRolesAndClientAllowList() {
        assertThat(mapper.map(PrincipalType.SERVICE, List.of(), List.of("Orders.Sync"), List.of(), "PEER-APP"))
                .containsExactlyInAnyOrder("ROLE_SYNC", "ROLE_PEER", "ROLE_SERVICE");
        assertThat(mapper.isKnownClient("peer-app")).isTrue();
        assertThat(mapper.isKnownClient("someone-else")).isFalse();
        assertThat(mapper.isKnownClient(null)).isFalse();
    }

    @Test
    void unmappedAppRolesCanBeDropped() {
        EntraAuthorityMapper strict = EntraAuthorityMapper.builder().mapUnmappedAppRoles(false)
                .appRoleMappings(Map.of("Known", List.of("K"))).build();
        assertThat(strict.map(PrincipalType.SERVICE, List.of(), List.of("Known", "Unknown"), List.of(), "x"))
                .containsExactly("ROLE_K");
    }

    @Test
    void scopesNeverGrantedToServices() {
        assertThat(mapper.map(PrincipalType.SERVICE, List.of(), List.of(), List.of("x"), null))
                .doesNotContain("SCOPE_x");
    }
}
