package io.github.rmkrdev.entra.security.test.obo;

import static io.github.rmkrdev.entra.security.test.EntraMockMvc.bearer;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.nimbusds.jwt.SignedJWT;

import io.github.rmkrdev.entra.security.test.AutoConfigureEntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraTestTokens;

/**
 * Spring MVC: a user calls this API, which calls a downstream API on the user's behalf through {@code RestClient},
 * with the token exchange served by the mock authority.
 */
@SpringBootTest(classes = OnBehalfOfServletApplication.class, properties = {
        "entra.security.outbound.clients.downstream.flow=on-behalf-of",
        "entra.security.outbound.clients.downstream.scope=api://downstream/Data.Read" })
@AutoConfigureMockMvc
@AutoConfigureEntraMockAuthority
class OnBehalfOfServletIntegrationTest {

    static final String ALICE = "a0a0a0a0-0000-4000-8000-0000000000c1";
    static final String BOB = "a0a0a0a0-0000-4000-8000-0000000000c2";

    @DynamicPropertySource
    static void downstream(DynamicPropertyRegistry registry) {
        registry.add("entra.security.outbound.clients.downstream.base-url", () -> DownstreamApi.shared().baseUrl());
    }

    @Autowired
    MockMvc mvc;

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
        String body = mvc.perform(get("/profile/downstream-token").with(bearer(tokens.user().objectId(ALICE))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        var claims = SignedJWT.parse(body).getJWTClaimsSet();
        assertThat(claims.getAudience()).containsExactly("api://downstream");
        assertThat(claims.getStringClaim("oid")).isEqualTo(ALICE);
        assertThat(claims.getStringClaim("scp")).isEqualTo("Data.Read");
        assertThat(claims.getStringClaim("azp")).isEqualTo(tokens.clientId());
    }

    @Test
    void tokensAreCachedPerUser() throws Exception {
        mvc.perform(get("/profile/downstream-token").with(bearer(tokens.user().objectId(ALICE))))
                .andExpect(status().isOk());
        mvc.perform(get("/profile/downstream-token").with(bearer(tokens.user().objectId(ALICE))))
                .andExpect(status().isOk());
        assertThat(authority.onBehalfOfRequests()).isEqualTo(1);

        mvc.perform(get("/profile/downstream-token").with(bearer(tokens.user().objectId(BOB))))
                .andExpect(status().isOk())
                .andExpect(content().string(startsWith("ey")));
        assertThat(authority.onBehalfOfRequests()).isEqualTo(2);
    }

    @Test
    void missingConsentIsA403Problem() throws Exception {
        authority.requireConsent("api://downstream/Data.Read");

        mvc.perform(get("/profile/downstream-token").with(bearer(tokens.user().objectId("consent-" + ALICE))))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(header().string("WWW-Authenticate", startsWith("Bearer error=\"consent_required\"")))
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.error").value("consent_required"))
                .andExpect(jsonPath("$.scope").value("api://downstream/Data.Read"))
                .andExpect(jsonPath("$.instance").value("/profile/downstream-token"));
    }

    @Test
    void conditionalAccessChallengeIsA403ProblemWithClaims() throws Exception {
        authority.requireInteraction("api://downstream", null);

        mvc.perform(get("/profile/downstream-token").with(bearer(tokens.user().objectId("mfa-" + ALICE))))
                .andExpect(status().isForbidden())
                .andExpect(header().string("WWW-Authenticate", startsWith("Bearer error=\"interaction_required\"")))
                .andExpect(jsonPath("$.error").value("interaction_required"))
                .andExpect(jsonPath("$.claims").value(org.hamcrest.Matchers.containsString("capolids")));
    }
}
