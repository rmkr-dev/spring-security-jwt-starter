package io.github.rmkrdev.entra.security.test.it;

import static io.github.rmkrdev.entra.security.test.EntraMockMvc.bearer;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.web.servlet.MockMvc;

import io.github.rmkrdev.entra.security.test.AutoConfigureEntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraTestTokens;

@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureEntraMockAuthority
class MockAuthorityIntegrationTest {

    static final String READERS = "aaaaaaaa-0000-0000-0000-000000000001";

    @Autowired
    MockMvc mvc;

    @Autowired
    EntraTestTokens tokens;

    @Autowired
    EntraMockAuthority authority;

    @Autowired
    Environment environment;

    @BeforeEach
    void resetGroups() {
        authority.reset();
    }

    @Test
    void wiresTheContextToTheMockAuthority() {
        assertThat(environment.getProperty("entra.security.authority-host")).isEqualTo(authority.baseUrl());
        assertThat(environment.getProperty("entra.security.jwk-set-uri"))
                .isEqualTo(authority.jwkSetUri("11111111-1111-1111-1111-111111111111"));
        assertThat(tokens.tenantId()).isEqualTo("11111111-1111-1111-1111-111111111111");
        assertThat(tokens.clientId()).isEqualTo("22222222-2222-2222-2222-222222222222");
    }

    @Test
    void publicPathStillOpen() throws Exception {
        mvc.perform(get("/public/ping")).andExpect(status().isOk()).andExpect(content().string("pong"));
    }

    @Test
    void userInMappedGroupIsAllowed() throws Exception {
        mvc.perform(get("/orders").header("Authorization", tokens.user().groups(READERS).bearer()))
                .andExpect(status().isOk())
                .andExpect(content().string("orders"));
    }

    @Test
    void userWithoutMappedGroupIsForbidden() throws Exception {
        mvc.perform(get("/orders").with(bearer(tokens.user().groups("bbbbbbbb-0000-0000-0000-000000000009"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void principalReflectsTheToken() throws Exception {
        mvc.perform(get("/me").with(bearer(tokens.user().groups(READERS))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type").value("USER"))
                .andExpect(jsonPath("$.oid").value(EntraTestTokens.USER_OBJECT_ID))
                .andExpect(jsonPath("$.appId").value(EntraTestTokens.USER_CLIENT_APP_ID))
                .andExpect(jsonPath("$.roles", hasItem("ROLE_ORDERS_READ")))
                .andExpect(jsonPath("$.version").value("2.0"));
    }

    @Test
    void v1TokensAreAccepted() throws Exception {
        mvc.perform(get("/me").with(bearer(tokens.user().v1().groups(READERS))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value("1.0"))
                .andExpect(jsonPath("$.appId").value(EntraTestTokens.USER_CLIENT_APP_ID));
    }

    @Test
    void serviceWithMappedAppRoleIsAllowed() throws Exception {
        mvc.perform(get("/internal/sync").with(bearer(tokens.service().appRoles("Orders.Sync"))))
                .andExpect(status().isOk());
        mvc.perform(get("/me").with(bearer(tokens.service())))
                .andExpect(jsonPath("$.type").value("SERVICE"))
                .andExpect(jsonPath("$.oid").value(EntraTestTokens.SERVICE_OBJECT_ID));
    }

    @Test
    void serviceIsMappedByClientId() throws Exception {
        mvc.perform(get("/internal/reports").with(bearer(tokens.service())))
                .andExpect(status().isForbidden());
        mvc.perform(get("/internal/reports").with(bearer(tokens.service().appId("c0c0c0c0-0000-4000-8000-000000000003"))))
                .andExpect(status().isOk());
    }

    @Test
    void groupOverageIsResolvedThroughTheMockGraph() throws Exception {
        String oid = "a0a0a0a0-0000-4000-8000-0000000000aa";
        authority.registerGroups(oid, Map.of("dddddddd-0000-0000-0000-000000000001", "Overage Readers"));
        mvc.perform(get("/orders").with(bearer(tokens.user().objectId(oid).groupOverage())))
                .andExpect(status().isOk());
        assertThat(authority.graphRequests()).isEqualTo(1);
        assertThat(authority.tokenRequests()).isGreaterThanOrEqualTo(1);
    }

    @Test
    void invalidTokensAreRejected() throws Exception {
        mvc.perform(get("/orders").with(bearer(tokens.user().groups(READERS).expired())))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/orders").with(bearer(tokens.user().groups(READERS).signedWithUnknownKey())))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/orders").with(bearer(tokens.user().groups(READERS).signedWithHmac())))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/orders").with(bearer(tokens.user().groups(READERS).audience("api://someone-else"))))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/orders").with(bearer(tokens.user().groups(READERS)
                .tenantId("99999999-9999-9999-9999-999999999999"))))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/orders").with(bearer(tokens.user().groups(READERS).expiresIn(Duration.ofMinutes(-10)))))
                .andExpect(status().isUnauthorized());
    }
}
