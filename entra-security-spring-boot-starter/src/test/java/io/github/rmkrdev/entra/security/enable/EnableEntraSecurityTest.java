package io.github.rmkrdev.entra.security.enable;

import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.moreThanOrExactly;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.github.rmkrdev.entra.security.support.EntraTestServer.TOKENS;
import static io.github.rmkrdev.entra.security.support.EntraTestServer.WIRE_MOCK;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import io.github.rmkrdev.entra.security.EntraSecurityPreloader;
import io.github.rmkrdev.entra.security.core.test.TestTokens;
import io.github.rmkrdev.entra.security.support.EntraTestServer;

/**
 * {@code @EnableEntraSecurity} turns method security on even when the property disables it, and
 * preloads the signing keys at startup.
 */
@SpringBootTest(properties = "entra.security.method-security.enabled=false")
@AutoConfigureMockMvc
class EnableEntraSecurityTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    EntraSecurityPreloader preloader;

    @DynamicPropertySource
    static void entra(DynamicPropertyRegistry registry) {
        EntraTestServer.register(registry);
    }

    @Test
    void preloadsJwksAtStartup() {
        assertThat(preloader.getLoadedKeys()).isEqualTo(1);
        WIRE_MOCK.verify(moreThanOrExactly(1),
                getRequestedFor(urlEqualTo("/" + TestTokens.TENANT_ID + "/discovery/v2.0/keys")));
    }

    @Test
    void securedIsEnforcedByTheAnnotation() throws Exception {
        mvc.perform(get("/secured").header("Authorization", "Bearer "
                + TOKENS.user().groups("aaaaaaaa-0000-0000-0000-000000000001").build()))
                .andExpect(status().isOk());
        mvc.perform(get("/secured").header("Authorization", "Bearer " + TOKENS.user().build()))
                .andExpect(status().isForbidden());
    }
}
