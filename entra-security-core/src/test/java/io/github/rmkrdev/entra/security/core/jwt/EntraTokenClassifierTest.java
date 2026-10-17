package io.github.rmkrdev.entra.security.core.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

class EntraTokenClassifierTest {

    private final EntraTokenClassifier classifier = new EntraTokenClassifier();

    @Test
    void idtypWins() {
        assertThat(classifier.classify(jwt(Map.of("idtyp", "app", "scp", "x")))).isEqualTo(PrincipalType.SERVICE);
        assertThat(classifier.classify(jwt(Map.of("idtyp", "user")))).isEqualTo(PrincipalType.USER);
    }

    @Test
    void scpPresenceDecidesWithoutIdtyp() {
        assertThat(classifier.classify(jwt(Map.of("scp", "access_as_user")))).isEqualTo(PrincipalType.USER);
        assertThat(classifier.classify(jwt(Map.of("roles", List.of("Sync"))))).isEqualTo(PrincipalType.SERVICE);
        assertThat(classifier.classify(jwt(Map.of("scp", " ")))).isEqualTo(PrincipalType.SERVICE);
    }

    @Test
    void claimHelpers() {
        Jwt v1 = jwt(Map.of("appid", "v1-app", "scp", "a b", "upn", "u@x", "hasgroups", true));
        assertThat(EntraClaims.appId(v1)).isEqualTo("v1-app");
        assertThat(EntraClaims.scopes(v1)).containsExactly("a", "b");
        assertThat(EntraClaims.username(v1)).isEqualTo("u@x");
        assertThat(EntraClaims.isGroupOverage(v1)).isTrue();

        Jwt v2 = jwt(Map.of("azp", "v2-app", "appid", "ignored", "_claim_names", Map.of("groups", "src1")));
        assertThat(EntraClaims.appId(v2)).isEqualTo("v2-app");
        assertThat(EntraClaims.isGroupOverage(v2)).isTrue();
        assertThat(EntraClaims.isGroupOverage(jwt(Map.of("groups", List.of("g"))))).isFalse();
    }

    static Jwt jwt(Map<String, Object> claims) {
        return Jwt.withTokenValue("t").header("alg", "RS256").claims(c -> c.putAll(claims))
                .claim("sub", "s").issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
    }
}
