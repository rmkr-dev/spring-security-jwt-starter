package io.github.rmkrdev.entra.security.core.authority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.github.rmkrdev.entra.security.core.authority.CompactRoleMappings.KeyType;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

class CompactRoleMappingsTest {

    private static final String G1 = "0b5c1d7e-1111-4a4a-9b9b-000000000001";
    private static final String G2 = "0b5c1d7e-1111-4a4a-9b9b-000000000002";
    private static final String PROPERTY = "entra.security.group-role-mappings-compact";

    @Test
    void parsesEntriesSeparatedBySemicolonsAndCommas() {
        Map<String, List<String>> mappings = CompactRoleMappings.parse(PROPERTY,
                G1 + "=ADMIN," + G1 + "=READER;" + G2 + "=READER", KeyType.GROUP);

        assertThat(mappings).containsExactly(Map.entry(G1, List.of("ADMIN", "READER")),
                Map.entry(G2, List.of("READER")));
    }

    @Test
    void pipeSeparatesSeveralRolesAndWhitespaceIsIgnored() {
        Map<String, List<String>> mappings = CompactRoleMappings.parse(PROPERTY,
                "  " + G1 + " = ADMIN | ROLE_READER ;\n " + G2 + "=READER|READER ; ;", KeyType.GROUP);

        assertThat(mappings).containsExactly(Map.entry(G1, List.of("ADMIN", "ROLE_READER")),
                Map.entry(G2, List.of("READER")));
    }

    @Test
    void blankValueIsEmpty() {
        assertThat(CompactRoleMappings.parse(PROPERTY, null, KeyType.GROUP)).isEmpty();
        assertThat(CompactRoleMappings.parse(PROPERTY, "  ", KeyType.GROUP)).isEmpty();
        assertThat(CompactRoleMappings.parse(PROPERTY, ";,", KeyType.GROUP)).isEmpty();
    }

    @Test
    void groupNamesMayContainSpaces() {
        assertThat(CompactRoleMappings.parse(PROPERTY, "Order Admins=ADMIN", KeyType.GROUP))
                .containsExactly(Map.entry("Order Admins", List.of("ADMIN")));
    }

    @Test
    void missingEqualsNamesTheEntry() {
        assertThatThrownBy(() -> CompactRoleMappings.parse(PROPERTY, G1 + "=ADMIN;" + G2, KeyType.GROUP))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(PROPERTY + ": entry 2 '" + G2 + "' is missing '='; expected <group>=<ROLE>[|<ROLE>...]");
    }

    @Test
    void emptyKeyAndEmptyRolesAreRejected() {
        assertThatThrownBy(() -> CompactRoleMappings.parse(PROPERTY, "=ADMIN", KeyType.GROUP))
                .hasMessageContaining("entry 1 '=ADMIN' has no group before '='");
        assertThatThrownBy(() -> CompactRoleMappings.parse(PROPERTY, G1 + "=", KeyType.GROUP))
                .hasMessageContaining("has no role after '='");
        assertThatThrownBy(() -> CompactRoleMappings.parse(PROPERTY, G1 + "=ADMIN||READER", KeyType.GROUP))
                .hasMessageContaining("has an empty role");
    }

    @Test
    void missingSeparatorBetweenEntriesIsExplained() {
        assertThatThrownBy(() -> CompactRoleMappings.parse(PROPERTY, G1 + "=ADMIN " + G2 + "=READER",
                KeyType.GROUP)).hasMessageContaining("contains more than one '='; separate entries with ';' or ','");
        assertThatThrownBy(() -> CompactRoleMappings.parse(PROPERTY, G1 + "=ADMIN READER", KeyType.GROUP))
                .hasMessageContaining("has role 'ADMIN READER' with whitespace in it; separate roles with '|'");
    }

    @Test
    void appRolesMustNotContainWhitespace() {
        assertThat(CompactRoleMappings.parse("p", "Orders.Read=READER", KeyType.APP_ROLE))
                .containsEntry("Orders.Read", List.of("READER"));
        assertThatThrownBy(() -> CompactRoleMappings.parse("p", "Orders Read=READER", KeyType.APP_ROLE))
                .hasMessage("p: entry 1 'Orders Read=READER' has app role 'Orders Read' with whitespace in it");
    }

    @Test
    void clientIdsMustBeGuids() {
        assertThat(CompactRoleMappings.parse("p", G1 + "=SERVICE", KeyType.CLIENT_ID)).containsKey(G1);
        assertThatThrownBy(() -> CompactRoleMappings.parse("p", "orders-api=SERVICE", KeyType.CLIENT_ID))
                .hasMessageContaining("has client id 'orders-api', which is not a GUID");
    }

    @Test
    void mergeCombinesRolesForTheSameKeyIgnoringCase() {
        Map<String, List<String>> map = new LinkedHashMap<>();
        map.put(G1.toUpperCase(), List.of("ADMIN"));
        map.put("other", List.of("READER"));
        Map<String, List<String>> merged = CompactRoleMappings.merge(map,
                Map.of(G1, List.of("ADMIN", "AUDITOR")), null, Map.of(G2, List.of(" READER ")));

        assertThat(merged).containsExactly(Map.entry(G1.toUpperCase(), List.of("ADMIN", "AUDITOR")),
                Map.entry("other", List.of("READER")), Map.entry(G2, List.of("READER")));
    }

    @Test
    void mergedMappingsDriveTheAuthorityMapper() {
        Map<String, List<String>> merged = CompactRoleMappings.merge(Map.of(G1, List.of("ADMIN")),
                CompactRoleMappings.parse(PROPERTY, G1 + "=READER;" + G2 + "=READER", KeyType.GROUP));
        EntraAuthorityMapper mapper = EntraAuthorityMapper.builder().groupRoleMappings(merged).build();

        assertThat(mapper.map(PrincipalType.USER, List.of(G1.toUpperCase()), List.of(), List.of(), null))
                .containsExactly("ROLE_ADMIN", "ROLE_READER");
        assertThat(mapper.map(PrincipalType.USER, List.of(G2), List.of(), List.of(), null))
                .containsExactly("ROLE_READER");
    }
}
