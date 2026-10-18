package io.github.rmkrdev.entra.security.autoconfigure.it;

import static io.github.rmkrdev.entra.security.support.EntraTestServer.WIRE_MOCK;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import io.github.rmkrdev.entra.security.support.EntraTestServer;

@SpringBootTest(properties = {
        "management.endpoint.health.show-details=always",
        "management.endpoint.health.show-components=always",
        "management.endpoints.web.exposure.include=health",
        "entra.security.graph.overage-enabled=false",
        "entra.security.public-paths=/actuator/health,/actuator/health/**" })
@AutoConfigureMockMvc
class EntraJwksDownHealthIntegrationTest {

    @Autowired
    MockMvc mvc;

    @DynamicPropertySource
    static void entra(DynamicPropertyRegistry registry) {
        EntraTestServer.register(registry);
        registry.add("entra.security.jwk-set-uri", () -> WIRE_MOCK.baseUrl() + "/missing-keys");
    }

    @Test
    void healthIsDownWhenJwksCannotBeLoadedAndGraphIsOmitted() throws Exception {
        mvc.perform(get("/actuator/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("DOWN"))
                .andExpect(jsonPath("$.components.entraJwks.status").value("DOWN"))
                .andExpect(jsonPath("$.components.entraJwks.details.reason").value("unreachable"))
                .andExpect(jsonPath("$.components.entraGraph").doesNotExist());
    }
}
