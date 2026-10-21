package io.github.rmkrdev.entra.security.test.reactive;

import static io.github.rmkrdev.entra.security.test.EntraWebTestClient.bearer;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.web.reactive.server.WebTestClient;

import io.github.rmkrdev.entra.security.core.jwt.EntraReactiveJwtDecoder;
import io.github.rmkrdev.entra.security.test.AutoConfigureEntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraTestTokens;
import io.github.rmkrdev.entra.security.test.EntraTestTokens.TokenBuilder;

/**
 * The WebFlux resource server against the mock authority: the same tokens, checks, role mapping, Graph lookup
 * and problem-details responses as the servlet stack.
 */
@SpringBootTest(properties = "spring.main.web-application-type=reactive")
@AutoConfigureWebTestClient
@AutoConfigureEntraMockAuthority
class ReactiveMockAuthorityIntegrationTest {

    static final String READERS = "aaaaaaaa-0000-0000-0000-000000000001";
    static final String OVERAGE_USER = "a0a0a0a0-0000-4000-8000-0000000000aa";

    @Autowired
    WebTestClient client;

    @Autowired
    EntraTestTokens tokens;

    @Autowired
    EntraMockAuthority authority;

    @Autowired
    ReactiveJwtDecoder decoder;

    @BeforeEach
    void resetGroups() {
        authority.reset();
    }

    @Test
    void usesTheEntraReactiveDecoder() {
        assertThat(decoder).isInstanceOf(EntraReactiveJwtDecoder.class);
    }

    // ------------------------------------------------------------------ public paths and 401s

    @Test
    void publicPathNeedsNoToken() {
        client.get().uri("/public/ping").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("pong");
        client.get().uri("/public/whoami").exchange()
                .expectBody(String.class).isEqualTo("anonymous");
    }

    @Test
    void authTimingIsReturnedAsServerTiming() {
        client.get().uri("/orders").headers(bearer(tokens.user().groups(READERS))).exchange()
                .expectStatus().isOk()
                .expectHeader().valueMatches("Server-Timing", "auth;dur=.*");
        client.get().uri("/orders").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches("Server-Timing", "auth;dur=.*");
        client.get().uri("/admin").headers(bearer(tokens.user().groups(READERS))).exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueMatches("Server-Timing", "auth;dur=.*");
        client.get().uri("/public/ping").exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("Server-Timing");
    }

    @Test
    void missingTokenIs401ProblemJson() {
        client.get().uri("/orders").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches("WWW-Authenticate", "Bearer.*")
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.title").isEqualTo("Unauthorized")
                .jsonPath("$.instance").isEqualTo("/orders")
                .jsonPath("$.error").isEqualTo("unauthorized");
    }

    @Test
    void malformedTokenIs401InvalidToken() {
        client.get().uri("/orders").headers(bearer("not-a-jwt")).exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches("WWW-Authenticate", ".*invalid_token.*")
                .expectBody()
                .jsonPath("$.error").isEqualTo("invalid_token");
    }

    @Test
    void invalidTokensAreRejectedLikeOnTheServletStack() {
        List<TokenBuilder> invalid = List.of(
                tokens.user().groups(READERS).expired(),
                tokens.user().groups(READERS).notBefore(Instant.now().plus(Duration.ofHours(1))),
                tokens.user().groups(READERS).audience("api://someone-else"),
                tokens.user().groups(READERS).issuer("https://evil.example/"),
                tokens.user().groups(READERS).tenantId("99999999-9999-4999-8999-999999999999"),
                tokens.user().groups(READERS).signedWithUnknownKey(),
                tokens.user().groups(READERS).signedWithHmac(),
                tokens.user().groups(READERS).without("aud"));
        for (TokenBuilder token : invalid) {
            client.get().uri("/orders").headers(bearer(token)).exchange()
                    .expectStatus().isUnauthorized()
                    .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                    .expectBody().jsonPath("$.error").isEqualTo("invalid_token");
        }
    }

    // ------------------------------------------------------------------ user flow

    @Test
    void userInMappedGroupPassesSecured() {
        client.get().uri("/orders").headers(bearer(tokens.user().groups(READERS))).exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("orders");
    }

    @Test
    void v1TokensAreAccepted() {
        client.get().uri("/orders").headers(bearer(tokens.user().groups(READERS).v1())).exchange()
                .expectStatus().isOk();
    }

    @Test
    void userWithoutRoleIs403ProblemJson() {
        client.get().uri("/admin").headers(bearer(tokens.user().groups(READERS))).exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueMatches("WWW-Authenticate", ".*insufficient_scope.*")
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.status").isEqualTo(403)
                .jsonPath("$.title").isEqualTo("Forbidden")
                .jsonPath("$.error").isEqualTo("insufficient_scope")
                .jsonPath("$.instance").isEqualTo("/admin");
    }

    @Test
    void userInUnmappedGroupIs403() {
        client.get().uri("/orders").headers(bearer(tokens.user().groups("bbbbbbbb-0000-0000-0000-000000000009")))
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void appRoleFromTheTokenWorksWithPreAuthorize() {
        client.post().uri("/orders").headers(bearer(tokens.user().appRoles("ORDERS_WRITE"))).exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("created");
        client.post().uri("/orders").headers(bearer(tokens.user().groups(READERS))).exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("insufficient_scope");
    }

    @Test
    void groupOverageIsResolvedThroughGraphByIdAndName() {
        authority.registerGroups(OVERAGE_USER, Map.of("cccccccc-0000-0000-0000-000000000003", "Overage Readers"));
        client.get().uri("/orders").headers(bearer(tokens.user().objectId(OVERAGE_USER).groupOverage())).exchange()
                .expectStatus().isOk();
        client.get().uri("/me").headers(bearer(tokens.user().objectId(OVERAGE_USER).groupOverage())).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.groups[0]").isEqualTo("cccccccc-0000-0000-0000-000000000003")
                .jsonPath("$.roles").value(roles -> assertThat(roles)
                        .asInstanceOf(InstanceOfAssertFactories.list(String.class))
                        .contains("ROLE_ORDERS_READ"));
        assertThat(authority.graphRequests()).isEqualTo(1);
    }

    @Test
    void overageWithoutGraphGroupsGrantsNoGroupRole() {
        client.get().uri("/orders").headers(bearer(tokens.user().objectId("a0a0a0a0-0000-4000-8000-0000000000ab")
                .groupOverage())).exchange()
                .expectStatus().isForbidden();
    }

    // ------------------------------------------------------------------ service flow

    @Test
    void serviceAppRoleIsMapped() {
        client.get().uri("/internal/sync").headers(bearer(tokens.service().appRoles("Orders.Sync"))).exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("synced");
        client.get().uri("/internal/sync").headers(bearer(tokens.service())).exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void serviceClientIdIsMapped() {
        client.get().uri("/internal/reports").headers(bearer(tokens.service()
                .appId("c0c0c0c0-0000-4000-8000-000000000003"))).exchange()
                .expectStatus().isOk();
    }

    // ------------------------------------------------------------------ principal

    @Test
    void principalIsResolvableInEveryForm() {
        TokenBuilder user = tokens.user().groups(READERS).objectId("a0a0a0a0-0000-4000-8000-0000000000bb");
        client.get().uri("/me").headers(bearer(user)).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.type").isEqualTo("USER")
                .jsonPath("$.oid").isEqualTo("a0a0a0a0-0000-4000-8000-0000000000bb")
                .jsonPath("$.appId").isEqualTo(EntraTestTokens.USER_CLIENT_APP_ID)
                .jsonPath("$.version").isEqualTo("2.0")
                .jsonPath("$.roles").value(roles -> assertThat(roles)
                        .asInstanceOf(InstanceOfAssertFactories.list(String.class))
                        .contains("ROLE_ORDERS_READ"));
        client.get().uri("/me/mono").headers(bearer(user)).exchange()
                .expectBody(String.class).isEqualTo("a0a0a0a0-0000-4000-8000-0000000000bb");
        client.get().uri("/me/current").headers(bearer(user)).exchange()
                .expectBody(String.class).isEqualTo("a0a0a0a0-0000-4000-8000-0000000000bb");
        client.get().uri("/me/annotated").headers(bearer(tokens.service())).exchange()
                .expectBody(String.class).isEqualTo("SERVICE");
        client.get().uri("/public/whoami").headers(bearer(user)).exchange()
                .expectBody(String.class).isEqualTo("a0a0a0a0-0000-4000-8000-0000000000bb");
    }
}
