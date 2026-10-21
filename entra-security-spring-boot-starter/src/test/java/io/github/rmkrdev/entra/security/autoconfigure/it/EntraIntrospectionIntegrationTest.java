package io.github.rmkrdev.entra.security.autoconfigure.it;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.micrometer.core.instrument.MeterRegistry;
import io.github.rmkrdev.entra.security.core.introspect.CachingTokenIntrospector;
import io.github.rmkrdev.entra.security.core.introspect.TokenIntrospector;
import io.github.rmkrdev.entra.security.core.test.TestTokens;

/**
 * {@code validation.mode=introspection} against an RFC 7662 endpoint of a custom gateway: opaque tokens, claims
 * mapping, caching, and fail-closed behaviour when the endpoint breaks.
 */
@SpringBootTest(properties = {
        "entra.security.validation.mode=introspection",
        "entra.security.validation.introspection.client-id=gateway-client",
        "entra.security.validation.introspection.client-secret=gateway-secret",
        "entra.security.validation.introspection.claims-mapping.oid=user_id",
        "entra.security.validation.introspection.failure-threshold=2",
        "entra.security.validation.introspection.open-duration=1h",
        "entra.security.graph.overage-enabled=false",
        "management.metrics.enable.all=true" })
@AutoConfigureMockMvc
class EntraIntrospectionIntegrationTest {

    static final WireMockServer GATEWAY = new WireMockServer(options().dynamicPort());

    static {
        GATEWAY.start();
        Runtime.getRuntime().addShutdownHook(new Thread(GATEWAY::stop));
    }

    @DynamicPropertySource
    static void gateway(DynamicPropertyRegistry registry) {
        registry.add("entra.security.validation.introspection.uri", () -> GATEWAY.baseUrl() + "/introspect");
        registry.add("entra.security.issuers", () -> "https://gateway.example");
    }

    @Autowired
    MockMvc mvc;

    @Autowired
    ApplicationContext context;

    @Autowired
    TokenIntrospector introspector;

    @BeforeEach
    void reset() {
        GATEWAY.resetAll();
        ((CachingTokenIntrospector) introspector).circuitBreaker().onSuccess();
    }

    static String active(String extra) {
        return "{\"active\":true,\"iss\":\"https://gateway.example\",\"aud\":\"" + TestTokens.CLIENT_ID + "\","
                + "\"tid\":\"" + TestTokens.TENANT_ID + "\",\"exp\":" + Instant.now().plusSeconds(600).getEpochSecond()
                + extra + "}";
    }

    @Test
    void activeServiceTokenIsMappedThroughAppRoles() throws Exception {
        GATEWAY.stubFor(post("/introspect").withRequestBody(containing("token=svc-opaque"))
                .willReturn(okJson(active(",\"client_id\":\"" + TestTokens.PEER_APP_ID
                        + "\",\"roles\":[\"Orders.Sync\"]"))));

        mvc.perform(MockMvcRequestBuilders.get("/internal/sync").header("Authorization", "Bearer svc-opaque"))
                .andExpect(status().isOk());
        mvc.perform(MockMvcRequestBuilders.get("/internal/sync").header("Authorization", "Bearer svc-opaque"))
                .andExpect(status().isOk());

        GATEWAY.verify(1, postRequestedFor(urlEqualTo("/introspect"))
                .withHeader("Authorization", containing("Basic "))
                .withRequestBody(containing("token_type_hint=access_token")));
        assertThat(introspector).isInstanceOf(CachingTokenIntrospector.class);
        assertThat(context.getBean(MeterRegistry.class).find("entra.security.introspection.requests")
                .tag("result", "active").timer()).isNotNull();
    }

    @Test
    void userTokenGetsGroupRolesAndMappedClaims() throws Exception {
        GATEWAY.stubFor(post("/introspect").withRequestBody(containing("token=user-opaque"))
                .willReturn(okJson(active(",\"scope\":\"access_as_user\",\"user_id\":\"u-1\","
                        + "\"groups\":[\"aaaaaaaa-0000-0000-0000-000000000001\"]"))));

        mvc.perform(MockMvcRequestBuilders.get("/me").header("Authorization", "Bearer user-opaque"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type").value("USER"))
                .andExpect(jsonPath("$.objectId").value("u-1"));
        mvc.perform(MockMvcRequestBuilders.get("/orders").header("Authorization", "Bearer user-opaque"))
                .andExpect(status().isOk());
    }

    @Test
    void inactiveAndWrongAudienceAreRejected() throws Exception {
        GATEWAY.stubFor(post("/introspect").withRequestBody(containing("token=revoked"))
                .willReturn(okJson("{\"active\":false}")));
        GATEWAY.stubFor(post("/introspect").withRequestBody(containing("token=foreign"))
                .willReturn(okJson(active(",\"aud\":\"someone-else\"").replace(
                        "\"aud\":\"" + TestTokens.CLIENT_ID + "\",", ""))));

        mvc.perform(MockMvcRequestBuilders.get("/me").header("Authorization", "Bearer revoked"))
                .andExpect(status().isUnauthorized());
        mvc.perform(MockMvcRequestBuilders.get("/me").header("Authorization", "Bearer foreign"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void brokenEndpointFailsClosedAndOpensTheCircuit() throws Exception {
        GATEWAY.stubFor(post("/introspect").willReturn(aResponse().withStatus(503)));

        for (String token : new String[] { "t1", "t2", "t3", "t4" }) {
            mvc.perform(MockMvcRequestBuilders.get("/me").header("Authorization", "Bearer " + token))
                    .andExpect(status().isUnauthorized());
        }
        // Two failures open the circuit; the next tokens are rejected without a call.
        GATEWAY.verify(2, postRequestedFor(urlEqualTo("/introspect")));
        GATEWAY.verify(0, postRequestedFor(urlEqualTo("/introspect")).withRequestBody(equalTo("token=t3")));
    }
}
