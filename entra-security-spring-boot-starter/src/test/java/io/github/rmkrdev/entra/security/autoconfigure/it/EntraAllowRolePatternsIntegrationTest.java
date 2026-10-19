package io.github.rmkrdev.entra.security.autoconfigure.it;

import static io.github.rmkrdev.entra.security.support.EntraTestServer.TOKENS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import io.github.rmkrdev.entra.security.support.EntraTestServer;

@SpringBootTest(properties = "entra.security.authorization.allow-role-patterns=*orders_r*,regex:nomatch")
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class EntraAllowRolePatternsIntegrationTest {

    private static final String READERS_GROUP = "aaaaaaaa-0000-0000-0000-000000000001";

    @Autowired
    MockMvc mvc;

    @DynamicPropertySource
    static void entra(DynamicPropertyRegistry registry) {
        EntraTestServer.register(registry);
    }

    @Test
    void matchingRoleOpensEveryApiAndIsLogged(CapturedOutput output) throws Exception {
        mvc.perform(get("/admin").header("Authorization", "Bearer " + TOKENS.user().groups(READERS_GROUP).build()))
                .andExpect(status().isOk());
        mvc.perform(get("/internal/reports").header("Authorization", "Bearer "
                + TOKENS.user().groups(READERS_GROUP).build())).andExpect(status().isOk());
        assertThat(output.getOut()).contains("granted by entra.security.authorization.allow-role-patterns")
                .contains("\"reason\":\"role_pattern\"");
    }

    @Test
    void otherRolesStillGetTheNormalChecks() throws Exception {
        String service = TOKENS.service().roles("Orders.Sync").build();
        mvc.perform(get("/internal/sync").header("Authorization", "Bearer " + service)).andExpect(status().isOk());
        mvc.perform(get("/admin").header("Authorization", "Bearer " + service)).andExpect(status().isForbidden());
        mvc.perform(get("/admin").header("Authorization", "Bearer " + TOKENS.user().build()))
                .andExpect(status().isForbidden());
        mvc.perform(get("/admin")).andExpect(status().isUnauthorized());
    }
}
