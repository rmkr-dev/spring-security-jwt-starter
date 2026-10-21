package io.github.rmkrdev.entra.sample.reactive;

import static io.github.rmkrdev.entra.security.test.EntraWebTestClient.bearer;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.ClassUtils;

import io.github.rmkrdev.entra.security.test.AutoConfigureEntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraTestTokens;
import io.github.rmkrdev.entra.security.test.WithMockEntraService;
import io.github.rmkrdev.entra.security.test.WithMockEntraUser;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * How a WebFlux service tests its endpoints with {@code entra-security-test} and {@code WebTestClient}: real
 * signed tokens against the mock authority, or {@code @WithMockEntraUser}/{@code @WithMockEntraService}.
 */
@SpringBootTest(properties = {
        "entra.security.tenant-id=11111111-1111-1111-1111-111111111111",
        "entra.security.client-id=22222222-2222-2222-2222-222222222222",
        "entra.security.group-role-mappings.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa=ORDERS_READ",
        "entra.security.app-role-mappings[Orders.Sync]=ORDERS_SYNC",
        "entra.security.graph.overage-enabled=true",
        "entra.security.credential.type=client-secret",
        "entra.security.credential.client-secret=test-secret" })
@AutoConfigureWebTestClient
@AutoConfigureEntraMockAuthority
class SampleReactiveApiApplicationTest {

    static final String READERS = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    @Autowired
    WebTestClient client;

    @Autowired
    EntraTestTokens tokens;

    @Autowired
    EntraMockAuthority authority;

    @Autowired
    MeterRegistry registry;

    @Test
    void runsWithoutTheServletApi() {
        assertThat(ClassUtils.isPresent("jakarta.servlet.http.HttpServletRequest", null)).isFalse();
    }

    @Test
    void healthIsPublicAndReportsJwksAndGraph() {
        client.get().uri("/actuator/health").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.components.entraJwks.status").isEqualTo("UP")
                .jsonPath("$.components.entraGraph.status").isEqualTo("UP");
    }

    @Test
    void ordersRequireGroupRole() {
        client.get().uri("/api/orders").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON);
        client.get().uri("/api/orders").headers(bearer(tokens.user().groups(READERS))).exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$[0].item").isEqualTo("keyboard");
        client.get().uri("/api/orders").headers(bearer(tokens.user())).exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("insufficient_scope");
    }

    @Test
    void writersCanCreate() {
        client.post().uri("/api/orders").headers(bearer(tokens.user().appRoles("ORDERS_WRITE")))
                .contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("item", "mouse")).exchange()
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.item").isEqualTo("mouse")
                .jsonPath("$.createdBy").isEqualTo(EntraTestTokens.USER_OBJECT_ID);
    }

    @Test
    void usersInManyGroupsAreResolvedThroughGraph() {
        String oid = "a0a0a0a0-0000-4000-8000-0000000000dd";
        authority.registerGroups(oid, READERS);
        client.get().uri("/api/orders").headers(bearer(tokens.user().objectId(oid).groupOverage())).exchange()
                .expectStatus().isOk();
        client.get().uri("/api/me").headers(bearer(tokens.user().objectId(oid).groupOverage())).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.objectId").isEqualTo(oid)
                .jsonPath("$.groups").value(hasItem(READERS))
                .jsonPath("$.roles").value(hasItem("ROLE_ORDERS_READ"));
    }

    @Test
    void peerServiceCanSync() {
        client.post().uri("/internal/orders/sync").headers(bearer(tokens.service().appRoles("Orders.Sync")))
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.callerAppId").isEqualTo(EntraTestTokens.SERVICE_APP_ID);
        client.post().uri("/internal/orders/sync").headers(bearer(tokens.user().groups(READERS))).exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void metricsAreAuthenticatedAndCountJwtSuccess() {
        client.get().uri("/actuator/metrics").exchange().expectStatus().isUnauthorized();
        double before = authentications("success", "none");
        client.get().uri("/api/orders").headers(bearer(tokens.user().groups(READERS))).exchange()
                .expectStatus().isOk();
        assertThat(authentications("success", "none")).isEqualTo(before + 1);
        double expired = authentications("failure", "expired");
        client.get().uri("/api/orders").headers(bearer(tokens.user().groups(READERS).expired())).exchange()
                .expectStatus().isUnauthorized();
        assertThat(authentications("failure", "expired")).isEqualTo(expired + 1);
    }

    @Test
    @WithMockEntraUser(groups = READERS)
    void annotationRunsAsAMappedUser() {
        client.get().uri("/api/orders").exchange().expectStatus().isOk();
    }

    @Test
    @WithMockEntraService(appRoles = "Orders.Sync")
    void annotationRunsAsAPeerService() {
        client.post().uri("/internal/orders/sync").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.callerAppId").isEqualTo(EntraTestTokens.SERVICE_APP_ID);
    }

    private double authentications(String result, String reason) {
        Counter counter = registry.find("entra.security.jwt.authentications").tag("result", result)
                .tag("reason", reason).counter();
        return counter == null ? 0 : counter.count();
    }
}
