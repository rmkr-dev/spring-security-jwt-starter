package io.github.rmkrdev.entra.security.autoconfigure.it;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.github.rmkrdev.entra.security.support.EntraTestServer.TOKENS;
import static io.github.rmkrdev.entra.security.support.EntraTestServer.WIRE_MOCK;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import io.github.rmkrdev.entra.security.core.test.TestTokens;
import io.github.rmkrdev.entra.security.support.EntraTestServer;

@SpringBootTest
@AutoConfigureMockMvc
class EntraSecurityIntegrationTest {

    static final String READERS_GROUP = "aaaaaaaa-0000-0000-0000-000000000001";

    @Autowired
    MockMvc mvc;

    @DynamicPropertySource
    static void entra(DynamicPropertyRegistry registry) {
        EntraTestServer.register(registry);
    }

    // ------------------------------------------------------------------ public paths and 401s

    @Test
    void publicPathNeedsNoToken() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/public/ping"))
                .andExpect(status().isOk())
                .andExpect(content().string("pong"));
    }

    @Test
    void missingTokenIs401ProblemJson() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/orders"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", startsWith("Bearer")))
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.title").value("Unauthorized"))
                .andExpect(jsonPath("$.instance").value("/orders"));
    }

    @Test
    void malformedTokenIs401() throws Exception {
        perform(MockMvcRequestBuilders.get("/orders"), "not-a-jwt")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_token"));
    }

    // ------------------------------------------------------------------ user flow

    @Test
    void userInMappedGroupGetsRole() throws Exception {
        perform(MockMvcRequestBuilders.get("/orders"), TOKENS.user().groups(READERS_GROUP).build())
                .andExpect(status().isOk())
                .andExpect(content().string("orders"));
    }

    @Test
    void userWithoutRoleIs403ProblemJson() throws Exception {
        perform(MockMvcRequestBuilders.get("/admin"), TOKENS.user().groups(READERS_GROUP).build())
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.error").value("insufficient_scope"))
                .andExpect(header().string("WWW-Authenticate", containsString("insufficient_scope")));
    }

    @Test
    void userInUnmappedGroupIs403() throws Exception {
        perform(MockMvcRequestBuilders.get("/orders"), TOKENS.user().groups(UUID.randomUUID().toString()).build())
                .andExpect(status().isForbidden());
    }

    @Test
    void userAppRoleFromEnterpriseAppAssignmentWorksWithPreAuthorize() throws Exception {
        perform(post("/orders"), TOKENS.user().roles("ORDERS_WRITE").build())
                .andExpect(status().isOk())
                .andExpect(content().string("created"));
        perform(post("/orders"), TOKENS.user().groups(READERS_GROUP).build())
                .andExpect(status().isForbidden());
    }

    @Test
    void userPrincipalIsInjectable() throws Exception {
        perform(MockMvcRequestBuilders.get("/me"), TOKENS.user().groups(READERS_GROUP).build())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type").value("USER"))
                .andExpect(jsonPath("$.objectId").value(TestTokens.USER_OID))
                .andExpect(jsonPath("$.tenantId").value(TestTokens.TENANT_ID))
                .andExpect(jsonPath("$.appId").value(TestTokens.SPA_APP_ID))
                .andExpect(jsonPath("$.roles", hasItem("ROLE_ORDERS_READ")))
                .andExpect(jsonPath("$.roles", hasItem("SCOPE_access_as_user")))
                .andExpect(jsonPath("$.groups", hasItem(READERS_GROUP)))
                .andExpect(jsonPath("$.scopes", hasItem("access_as_user")));
        perform(MockMvcRequestBuilders.get("/me/annotated"), TOKENS.user().build())
                .andExpect(jsonPath("$.type").value("USER"))
                .andExpect(jsonPath("$.name").value(TestTokens.USER_OID));
    }

    @Test
    void groupOverageResolvedThroughGraphAndCached() throws Exception {
        String oid = UUID.randomUUID().toString();
        String path = "/v1.0/users/" + oid + "/transitiveMemberOf";
        WIRE_MOCK.stubFor(get(urlPathEqualTo(path)).willReturn(okJson("{\"value\":[{\"@odata.type\":"
                + "\"#microsoft.graph.group\",\"id\":\"" + UUID.randomUUID() + "\",\"displayName\":\"Overage Group\"}]}")));
        String token = TOKENS.user().claim("oid", oid)
                .claim("_claim_names", Map.of("groups", "src1"))
                .claim("_claim_sources", Map.of("src1", Map.of("endpoint", "https://graph.windows.net/x/getMemberObjects")))
                .build();

        perform(MockMvcRequestBuilders.get("/orders"), token).andExpect(status().isOk());
        perform(MockMvcRequestBuilders.get("/orders"), token).andExpect(status().isOk());

        WIRE_MOCK.verify(1, getRequestedFor(urlPathEqualTo(path))
                .withHeader("Authorization", equalTo("Bearer app-token")));
    }

    @Test
    void groupOverageWithGraphFailureFailsClosed() throws Exception {
        String oid = UUID.randomUUID().toString();
        WIRE_MOCK.stubFor(get(urlPathEqualTo("/v1.0/users/" + oid + "/transitiveMemberOf"))
                .willReturn(com.github.tomakehurst.wiremock.client.WireMock.aResponse().withStatus(503)));
        perform(MockMvcRequestBuilders.get("/orders"), TOKENS.user().claim("oid", oid).claim("hasgroups", true).build())
                .andExpect(status().isForbidden());
    }

    @Test
    void v1TokenAccepted() throws Exception {
        String token = TOKENS.user().issuer(TestTokens.V1_ISSUER).audience("api://" + TestTokens.CLIENT_ID)
                .without("azp").claim("appid", TestTokens.SPA_APP_ID).claim("ver", "1.0")
                .groups(READERS_GROUP).build();
        perform(MockMvcRequestBuilders.get("/me"), token)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.appId").value(TestTokens.SPA_APP_ID))
                .andExpect(jsonPath("$.tokenVersion").value("1.0"));
    }

    // ------------------------------------------------------------------ service flow

    @Test
    void serviceAppRoleGrantsAccess() throws Exception {
        perform(MockMvcRequestBuilders.get("/internal/sync"), TOKENS.service().roles("Orders.Sync").build())
                .andExpect(status().isOk())
                .andExpect(content().string("synced"));
    }

    @Test
    void serviceWithoutAppRoleIs403() throws Exception {
        perform(MockMvcRequestBuilders.get("/internal/sync"), TOKENS.service().roles("Something.Else").build())
                .andExpect(status().isForbidden());
    }

    @Test
    void serviceClientAllowListGrantsRole() throws Exception {
        perform(MockMvcRequestBuilders.get("/internal/reports"), TOKENS.service().build())
                .andExpect(status().isOk());
        perform(MockMvcRequestBuilders.get("/internal/reports"),
                TOKENS.service().claim("azp", UUID.randomUUID().toString()).build())
                .andExpect(status().isForbidden());
    }

    @Test
    void serviceTokenWithoutIdtypIsDetectedByMissingScp() throws Exception {
        perform(MockMvcRequestBuilders.get("/me"), TOKENS.service().without("idtyp").roles("Orders.Sync").build())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type").value("SERVICE"))
                .andExpect(jsonPath("$.appId").value(TestTokens.PEER_APP_ID))
                .andExpect(jsonPath("$.roles", hasItem("ROLE_SYNC")))
                .andExpect(jsonPath("$.roles", hasItem("ROLE_REPORTS")));
    }

    @Test
    void userCannotUseServiceOnlyClientMappingThroughAzp() throws Exception {
        // client-role-mappings apply to app-only tokens only
        perform(MockMvcRequestBuilders.get("/internal/reports"),
                TOKENS.user().claim("azp", TestTokens.PEER_APP_ID).build())
                .andExpect(status().isForbidden());
    }

    // ------------------------------------------------------------------ token validation

    @Test
    void wrongAudienceIs401() throws Exception {
        perform(MockMvcRequestBuilders.get("/orders"), TOKENS.user().audience("api://someone-else")
                .groups(READERS_GROUP).build())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail", containsString("aud")));
    }

    @Test
    void wrongIssuerIs401() throws Exception {
        perform(MockMvcRequestBuilders.get("/orders"), TOKENS.user()
                .issuer("https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0")
                .groups(READERS_GROUP).build())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail", containsString("iss")));
    }

    @Test
    void wrongTenantIs401() throws Exception {
        perform(MockMvcRequestBuilders.get("/orders"), TOKENS.user()
                .claim("tid", "99999999-9999-9999-9999-999999999999").groups(READERS_GROUP).build())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail", containsString("tid")));
    }

    @Test
    void expiredTokenIs401() throws Exception {
        perform(MockMvcRequestBuilders.get("/orders"), TOKENS.user().groups(READERS_GROUP)
                .issuedAt(Instant.now().minusSeconds(7200)).expiresAt(Instant.now().minusSeconds(300)).build())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail", containsString("expired")));
    }

    @Test
    void recentlyExpiredTokenWithinClockSkewIsAccepted() throws Exception {
        perform(MockMvcRequestBuilders.get("/orders"), TOKENS.user().groups(READERS_GROUP)
                .issuedAt(Instant.now().minusSeconds(3600)).expiresAt(Instant.now().minusSeconds(20)).build())
                .andExpect(status().isOk());
    }

    @Test
    void hs256TokenIsRejected() throws Exception {
        perform(MockMvcRequestBuilders.get("/orders"), TOKENS.user().groups(READERS_GROUP).hmac().build())
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenSignedWithUnknownKeyIsRejected() throws Exception {
        perform(MockMvcRequestBuilders.get("/orders"), TOKENS.user().groups(READERS_GROUP).signedWithUnknownKey()
                .build())
                .andExpect(status().isUnauthorized());
    }

    @Test
    void sessionIsStatelessAndCsrfIsOff() throws Exception {
        perform(post("/orders"), TOKENS.user().roles("ORDERS_WRITE").build())
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    private ResultActions perform(MockHttpServletRequestBuilder request, String token) throws Exception {
        return mvc.perform(request.header("Authorization", "Bearer " + token));
    }
}
