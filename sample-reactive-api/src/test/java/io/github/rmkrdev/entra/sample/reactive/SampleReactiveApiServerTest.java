package io.github.rmkrdev.entra.sample.reactive;

import static io.github.rmkrdev.entra.security.test.EntraWebTestClient.bearer;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import io.github.rmkrdev.entra.security.test.AutoConfigureEntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraTestTokens;

/**
 * The same flows over a real Netty server, where token validation and the Graph lookup run off the event loop.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT, properties = {
        "entra.security.tenant-id=11111111-1111-1111-1111-111111111111",
        "entra.security.client-id=22222222-2222-2222-2222-222222222222",
        "entra.security.group-role-mappings.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa=ORDERS_READ",
        "entra.security.graph.overage-enabled=true",
        "entra.security.credential.type=client-secret",
        "entra.security.credential.client-secret=test-secret" })
@AutoConfigureEntraMockAuthority
class SampleReactiveApiServerTest {

    static final String READERS = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    @Autowired
    WebTestClient client;

    @Autowired
    EntraTestTokens tokens;

    @Autowired
    EntraMockAuthority authority;

    @Test
    void validatesMapsAndRejectsOverHttp() {
        client.get().uri("/api/orders").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON);
        client.get().uri("/api/orders").headers(bearer(tokens.user().groups(READERS))).exchange()
                .expectStatus().isOk();
        client.get().uri("/api/orders").headers(bearer(tokens.user())).exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("insufficient_scope");
    }

    @Test
    void groupOverageOverHttp() {
        String oid = "a0a0a0a0-0000-4000-8000-0000000000ee";
        authority.registerGroups(oid, READERS);
        client.get().uri("/api/orders").headers(bearer(tokens.user().objectId(oid).groupOverage())).exchange()
                .expectStatus().isOk();
    }
}
