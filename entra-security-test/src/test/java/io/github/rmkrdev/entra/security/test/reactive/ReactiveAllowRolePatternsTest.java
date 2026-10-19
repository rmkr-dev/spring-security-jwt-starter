package io.github.rmkrdev.entra.security.test.reactive;

import static io.github.rmkrdev.entra.security.test.EntraWebTestClient.bearer;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

import io.github.rmkrdev.entra.security.test.AutoConfigureEntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraTestTokens;

@SpringBootTest(properties = { "spring.main.web-application-type=reactive",
        "entra.security.authorization.allow-role-patterns=regex:orders_.*" })
@AutoConfigureWebTestClient
@AutoConfigureEntraMockAuthority
class ReactiveAllowRolePatternsTest {

    @Autowired
    WebTestClient client;

    @Autowired
    EntraTestTokens tokens;

    @Test
    void matchingRoleOpensSecuredEndpoints() {
        client.get().uri("/admin").headers(bearer(tokens.user().groups(ReactiveMockAuthorityIntegrationTest.READERS)))
                .exchange().expectStatus().isOk();
        client.get().uri("/admin").headers(bearer(tokens.user())).exchange().expectStatus().isForbidden();
        client.get().uri("/admin").exchange().expectStatus().isUnauthorized();
    }
}
