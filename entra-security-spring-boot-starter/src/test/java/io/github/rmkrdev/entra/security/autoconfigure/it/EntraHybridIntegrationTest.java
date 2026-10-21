package io.github.rmkrdev.entra.security.autoconfigure.it;

import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.github.rmkrdev.entra.security.support.EntraTestServer.TOKENS;
import static io.github.rmkrdev.entra.security.support.EntraTestServer.WIRE_MOCK;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import io.github.rmkrdev.entra.security.core.test.TestTokens;
import io.github.rmkrdev.entra.security.support.EntraTestServer;

/**
 * {@code validation.mode=hybrid}: Entra JWTs are validated with JWKS, then confirmed active by the remote check,
 * here authenticated with an app-only bearer token from this API's own credential.
 */
@SpringBootTest(properties = {
        "entra.security.validation.mode=hybrid",
        "entra.security.validation.introspection.auth-method=bearer",
        "entra.security.validation.introspection.scope=api://gateway/.default",
        "entra.security.validation.introspection.validate-claims=false" })
@AutoConfigureMockMvc
class EntraHybridIntegrationTest {

    @DynamicPropertySource
    static void entra(DynamicPropertyRegistry registry) {
        EntraTestServer.register(registry);
        registry.add("entra.security.validation.introspection.uri", () -> WIRE_MOCK.baseUrl() + "/hybrid/introspect");
    }

    @Autowired
    MockMvc mvc;

    @Test
    void validAndActiveTokenIsAccepted() throws Exception {
        String token = TOKENS.user().groups("aaaaaaaa-0000-0000-0000-000000000001").build();
        WIRE_MOCK.stubFor(post("/hybrid/introspect").withRequestBody(containing(token))
                .willReturn(okJson("{\"active\":true}")));
        mvc.perform(MockMvcRequestBuilders.get("/orders").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        WIRE_MOCK.verify(postRequestedFor(urlEqualTo("/hybrid/introspect"))
                .withHeader("Authorization", equalTo("Bearer app-token")));
        WIRE_MOCK.verify(postRequestedFor(urlPathEqualTo("/" + TestTokens.TENANT_ID + "/oauth2/v2.0/token"))
                .withRequestBody(containing("scope=api%3A%2F%2Fgateway%2F.default")));
    }

    @Test
    void revokedTokenIsRejectedEvenWithAValidSignature() throws Exception {
        String token = TOKENS.user().groups("aaaaaaaa-0000-0000-0000-000000000001").build();
        WIRE_MOCK.stubFor(post("/hybrid/introspect").willReturn(okJson("{\"active\":false}")));
        mvc.perform(MockMvcRequestBuilders.get("/orders").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void badSignatureNeverReachesTheRemoteCheck() throws Exception {
        String token = TOKENS.user().signedWithUnknownKey().build();
        mvc.perform(MockMvcRequestBuilders.get("/orders").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
        WIRE_MOCK.verify(0, postRequestedFor(urlEqualTo("/hybrid/introspect")).withRequestBody(containing(token)));
    }
}
