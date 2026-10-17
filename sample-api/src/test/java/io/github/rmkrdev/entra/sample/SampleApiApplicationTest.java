package io.github.rmkrdev.entra.sample;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.core.test.TestTokens;

@SpringBootTest(properties = {
        "entra.security.tenant-id=" + TestTokens.TENANT_ID,
        "entra.security.client-id=" + TestTokens.CLIENT_ID,
        "entra.security.group-role-mappings.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa=ORDERS_READ",
        "entra.security.app-role-mappings[Orders.Sync]=ORDERS_SYNC" })
@AutoConfigureMockMvc
class SampleApiApplicationTest {

    static final WireMockServer ENTRA = new WireMockServer(options().dynamicPort());
    static final TestTokens TOKENS;

    static {
        ENTRA.start();
        TOKENS = new TestTokens(ENTRA.baseUrl());
        ENTRA.stubFor(get("/" + TestTokens.TENANT_ID + "/discovery/v2.0/keys").willReturn(okJson(TOKENS.jwksJson())));
    }

    @Autowired
    MockMvc mvc;

    @DynamicPropertySource
    static void entra(DynamicPropertyRegistry registry) {
        registry.add("entra.security.authority-host", ENTRA::baseUrl);
    }

    @AfterAll
    static void stop() {
        ENTRA.stop();
    }

    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void ordersRequireGroupRole() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/api/orders")).andExpect(status().isUnauthorized());
        mvc.perform(MockMvcRequestBuilders.get("/api/orders")
                .header("Authorization", "Bearer " + TOKENS.user().groups("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").build()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].item").value("keyboard"));
        mvc.perform(MockMvcRequestBuilders.get("/api/orders")
                .header("Authorization", "Bearer " + TOKENS.user().build()))
                .andExpect(status().isForbidden());
    }

    @Test
    void peerServiceCanSync() throws Exception {
        mvc.perform(post("/internal/orders/sync")
                .header("Authorization", "Bearer " + TOKENS.service().roles("Orders.Sync").build()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.callerAppId").value(TestTokens.PEER_APP_ID));
        mvc.perform(post("/internal/orders/sync").contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + TOKENS.user().groups("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").build()))
                .andExpect(status().isForbidden());
    }
}
