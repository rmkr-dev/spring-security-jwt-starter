package io.github.rmkrdev.entra.security.test.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import io.github.rmkrdev.entra.security.core.principal.EntraPrincipals;
import io.github.rmkrdev.entra.security.test.EntraTestTokens;
import io.github.rmkrdev.entra.security.test.WithMockEntraService;
import io.github.rmkrdev.entra.security.test.WithMockEntraUser;

/**
 * No mock authority here: the annotations work without any token or JWKS, through the real role mapping.
 */
@SpringBootTest
@AutoConfigureMockMvc
class WithMockEntraAnnotationsTest {

    @Autowired
    MockMvc mvc;

    @Test
    @WithMockEntraUser(groups = "aaaaaaaa-0000-0000-0000-000000000001")
    void groupsGoThroughTheConfiguredMapping() throws Exception {
        mvc.perform(get("/orders")).andExpect(status().isOk());
        mvc.perform(get("/admin")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockEntraUser
    void userWithoutGroupsIsForbidden() throws Exception {
        mvc.perform(get("/orders")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockEntraUser(roles = "ADMIN")
    void extraRolesAreAdded() throws Exception {
        mvc.perform(get("/admin")).andExpect(status().isOk());
    }

    @Test
    @WithMockEntraUser(groups = "aaaaaaaa-0000-0000-0000-000000000001", objectId = "a0a0a0a0-0000-4000-8000-0000000000bb")
    void principalIsAvailableInTheTest() {
        EntraPrincipal principal = EntraPrincipals.require();
        assertThat(principal.isUser()).isTrue();
        assertThat(principal.objectId()).isEqualTo("a0a0a0a0-0000-4000-8000-0000000000bb");
        assertThat(principal.tenantId()).isEqualTo("11111111-1111-1111-1111-111111111111");
        assertThat(principal.hasRole("ORDERS_READ")).isTrue();
        assertThat(principal.scopes()).containsExactly("access_as_user");
    }

    @Test
    @WithMockEntraService(appRoles = "Orders.Sync")
    void serviceAppRolesAreMapped() throws Exception {
        mvc.perform(get("/internal/sync")).andExpect(status().isOk());
        mvc.perform(get("/me"))
                .andExpect(jsonPath("$.type").value("SERVICE"))
                .andExpect(jsonPath("$.appId").value(EntraTestTokens.SERVICE_APP_ID));
    }

    @Test
    @WithMockEntraService(appId = "c0c0c0c0-0000-4000-8000-000000000003")
    void serviceClientIdIsMapped() throws Exception {
        mvc.perform(get("/internal/reports")).andExpect(status().isOk());
        mvc.perform(get("/internal/sync")).andExpect(status().isForbidden());
    }

    @Test
    void anonymousIsStillUnauthorized() throws Exception {
        mvc.perform(get("/orders")).andExpect(status().isUnauthorized());
    }
}
