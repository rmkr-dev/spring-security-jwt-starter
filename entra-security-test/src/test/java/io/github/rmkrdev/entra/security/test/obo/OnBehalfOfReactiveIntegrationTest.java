package io.github.rmkrdev.entra.security.test.obo;

import static io.github.rmkrdev.entra.security.test.EntraWebTestClient.bearer;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.nimbusds.jwt.SignedJWT;

import io.github.rmkrdev.entra.security.test.AutoConfigureEntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraTestTokens;

/**
 * WebFlux: the same on-behalf-of call through {@code WebClient}, with the user taken from the Reactor context.
 */
@SpringBootTest(classes = OnBehalfOfReactiveApplication.class, properties = {
        "spring.main.web-application-type=reactive",
        "entra.security.outbound.clients.downstream.flow=on-behalf-of",
        "entra.security.outbound.clients.downstream.scope=api://downstream/Data.Read" })
@AutoConfigureWebTestClient
@AutoConfigureEntraMockAuthority
class OnBehalfOfReactiveIntegrationTest {

    static final String ALICE = "a0a0a0a0-0000-4000-8000-0000000000d1";

    @DynamicPropertySource
    static void downstream(DynamicPropertyRegistry registry) {
        registry.add("entra.security.outbound.clients.downstream.base-url", () -> DownstreamApi.shared().baseUrl());
    }

    @Autowired
    WebTestClient client;

    @Autowired
    EntraTestTokens tokens;

    @Autowired
    EntraMockAuthority authority;

    @BeforeEach
    void reset() {
        authority.reset();
    }

    @Test
    void theDownstreamApiReceivesADelegatedTokenForTheCallingUser() throws Exception {
        String body = client.get().uri("/profile/downstream-token").headers(bearer(tokens.user().objectId(ALICE)))
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).returnResult().getResponseBody();

        var claims = SignedJWT.parse(body).getJWTClaimsSet();
        assertThat(claims.getAudience()).containsExactly("api://downstream");
        assertThat(claims.getStringClaim("oid")).isEqualTo(ALICE);
        assertThat(claims.getStringClaim("scp")).isEqualTo("Data.Read");

        client.get().uri("/profile/downstream-token").headers(bearer(tokens.user().objectId(ALICE))).exchange()
                .expectStatus().isOk();
        assertThat(authority.onBehalfOfRequests()).isEqualTo(1);
    }

    @Test
    void missingConsentIsA403Problem() {
        authority.requireConsent("api://downstream");

        client.get().uri("/profile/downstream-token").headers(bearer(tokens.user().objectId("consent-" + ALICE)))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectHeader().valueMatches("WWW-Authenticate", "Bearer error=\"consent_required\".*")
                .expectBody()
                .jsonPath("$.error").isEqualTo("consent_required")
                .jsonPath("$.instance").isEqualTo("/profile/downstream-token");
    }

    @Test
    void conditionalAccessChallengeIsA403ProblemWithClaims() {
        authority.requireInteraction("api://downstream/Data.Read", null);

        client.get().uri("/profile/downstream-token").headers(bearer(tokens.user().objectId("mfa-" + ALICE)))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueMatches("WWW-Authenticate", ".*claims=\".*")
                .expectBody()
                .jsonPath("$.error").isEqualTo("interaction_required")
                .jsonPath("$.claims").value(claims -> assertThat(claims.toString()).contains("capolids"));
    }
}
