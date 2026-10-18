package io.github.rmkrdev.entra.security.test.reactive;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

import io.github.rmkrdev.entra.security.test.EntraTestTokens;
import io.github.rmkrdev.entra.security.test.WithMockEntraService;
import io.github.rmkrdev.entra.security.test.WithMockEntraUser;

/**
 * {@code @WithMockEntraUser} and {@code @WithMockEntraService} on WebFlux: no token or JWKS, and the
 * annotation values go through the starter's reactive role mapping.
 */
@SpringBootTest(properties = "spring.main.web-application-type=reactive")
@AutoConfigureWebTestClient
class ReactiveWithMockEntraAnnotationsTest {

    @Autowired
    WebTestClient client;

    @Test
    @WithMockEntraUser(groups = "aaaaaaaa-0000-0000-0000-000000000001")
    void groupsGoThroughTheConfiguredMapping() {
        client.get().uri("/orders").exchange().expectStatus().isOk();
        client.get().uri("/admin").exchange().expectStatus().isForbidden();
    }

    @Test
    @WithMockEntraUser
    void userWithoutGroupsIsForbidden() {
        client.get().uri("/orders").exchange().expectStatus().isForbidden();
    }

    @Test
    @WithMockEntraUser(roles = "ADMIN", objectId = "a0a0a0a0-0000-4000-8000-0000000000cc")
    void extraRolesAndPrincipal() {
        client.get().uri("/admin").exchange().expectStatus().isOk();
        client.get().uri("/me/mono").exchange().expectBody(String.class)
                .isEqualTo("a0a0a0a0-0000-4000-8000-0000000000cc");
    }

    @Test
    @WithMockEntraService(appRoles = "Orders.Sync")
    void serviceAppRolesAreMapped() {
        client.get().uri("/internal/sync").exchange().expectStatus().isOk();
        client.get().uri("/me").exchange().expectBody()
                .jsonPath("$.type").isEqualTo("SERVICE")
                .jsonPath("$.appId").isEqualTo(EntraTestTokens.SERVICE_APP_ID);
    }

    @Test
    @WithMockEntraService(appId = "c0c0c0c0-0000-4000-8000-000000000003")
    void serviceClientIdIsMapped() {
        client.get().uri("/internal/reports").exchange().expectStatus().isOk();
        client.get().uri("/internal/sync").exchange().expectStatus().isForbidden();
    }

    @Test
    void anonymousIsStillUnauthorized() {
        client.get().uri("/orders").exchange().expectStatus().isUnauthorized();
    }
}
