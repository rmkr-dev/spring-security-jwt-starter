package io.github.rmkrdev.entra.sample;

import static io.github.rmkrdev.entra.security.test.EntraMockMvc.bearer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import io.github.rmkrdev.entra.security.test.AutoConfigureEntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraTestTokens;
import io.github.rmkrdev.entra.security.test.WithMockEntraService;
import io.github.rmkrdev.entra.security.test.WithMockEntraUser;

/**
 * How a consuming service tests its endpoints with {@code entra-security-test}: real signed tokens against an
 * in-process mock authority, or {@code @WithMockEntraUser}/{@code @WithMockEntraService} with no token at all.
 */
@SpringBootTest(properties = {
        "entra.security.tenant-id=11111111-1111-1111-1111-111111111111",
        "entra.security.client-id=22222222-2222-2222-2222-222222222222",
        "entra.security.group-role-mappings.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa=ORDERS_READ",
        "entra.security.app-role-mappings[Orders.Sync]=ORDERS_SYNC" })
@AutoConfigureMockMvc
@AutoConfigureEntraMockAuthority
class SampleApiApplicationTest {

    static final String READERS = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    @Autowired
    MockMvc mvc;

    @Autowired
    EntraTestTokens tokens;

    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void ordersRequireGroupRole() throws Exception {
        mvc.perform(get("/api/orders")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/orders").with(bearer(tokens.user().groups(READERS))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].item").value("keyboard"));
        mvc.perform(get("/api/orders").with(bearer(tokens.user())))
                .andExpect(status().isForbidden());
    }

    @Test
    void peerServiceCanSync() throws Exception {
        mvc.perform(post("/internal/orders/sync").with(bearer(tokens.service().appRoles("Orders.Sync"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.callerAppId").value(EntraTestTokens.SERVICE_APP_ID));
        mvc.perform(post("/internal/orders/sync").contentType(MediaType.APPLICATION_JSON)
                .with(bearer(tokens.user().groups(READERS))))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockEntraUser(groups = READERS)
    void annotationRunsAsAMappedUser() throws Exception {
        mvc.perform(get("/api/orders")).andExpect(status().isOk());
    }

    @Test
    @WithMockEntraService(appRoles = "Orders.Sync")
    void annotationRunsAsAPeerService() throws Exception {
        mvc.perform(post("/internal/orders/sync"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.callerAppId").value(EntraTestTokens.SERVICE_APP_ID));
    }
}
