package io.github.rmkrdev.entra.security.autoconfigure.it;

import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.github.rmkrdev.entra.security.support.EntraTestServer.TOKENS;
import static io.github.rmkrdev.entra.security.support.EntraTestServer.WIRE_MOCK;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.github.tomakehurst.wiremock.client.WireMock;

import io.github.rmkrdev.entra.security.support.EntraTestServer;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

@SpringBootTest(properties = {
        "management.endpoint.health.show-details=always",
        "management.endpoint.health.show-components=always",
        "management.endpoints.web.exposure.include=health,metrics",
        "entra.security.public-paths=/actuator/health,/actuator/health/**,/public/**" })
@AutoConfigureMockMvc
class EntraObservabilityIntegrationTest {

    private static final String READERS_GROUP = "aaaaaaaa-0000-0000-0000-000000000001";

    @Autowired
    MockMvc mvc;

    @Autowired
    MeterRegistry registry;

    @DynamicPropertySource
    static void entra(DynamicPropertyRegistry registry) {
        EntraTestServer.register(registry);
    }

    @BeforeEach
    void graphProbe() {
        WIRE_MOCK.stubFor(WireMock.get(urlPathEqualTo("/v1.0/")).willReturn(ok()));
    }

    @Test
    void healthIsPublicAndReportsJwksAndGraph() throws Exception {
        mvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components.entraJwks.status").value("UP"))
                .andExpect(jsonPath("$.components.entraJwks.details.keys").isNumber())
                .andExpect(jsonPath("$.components.entraGraph.status").value("UP"))
                .andExpect(jsonPath("$.components.entraGraph.details.token").doesNotExist());
    }

    @Test
    void metricsRequireATokenAndRecordAuthentication() throws Exception {
        mvc.perform(get("/actuator/metrics")).andExpect(status().isUnauthorized());

        double missing = count("failure", "missing");
        mvc.perform(get("/orders")).andExpect(status().isUnauthorized());
        assertThat(count("failure", "missing")).isEqualTo(missing + 1);

        double success = count("success", "none");
        mvc.perform(get("/orders").header("Authorization", "Bearer "
                + TOKENS.user().groups(READERS_GROUP).build())).andExpect(status().isOk());
        assertThat(count("success", "none")).isEqualTo(success + 1);

        double malformed = count("failure", "malformed");
        mvc.perform(get("/orders").header("Authorization", "Bearer not-a-jwt")).andExpect(status().isUnauthorized());
        assertThat(count("failure", "malformed")).isEqualTo(malformed + 1);

        double expired = count("failure", "expired");
        mvc.perform(get("/orders").header("Authorization", "Bearer " + TOKENS.user().groups(READERS_GROUP)
                .issuedAt(Instant.now().minus(Duration.ofHours(2)))
                .expiresAt(Instant.now().minus(Duration.ofHours(1))).build()))
                .andExpect(status().isUnauthorized());
        assertThat(count("failure", "expired")).isEqualTo(expired + 1);

        mvc.perform(get("/orders").header("Authorization", "Bearer " + TOKENS.user().groups(READERS_GROUP).build()))
                .andExpect(status().isOk());
        mvc.perform(get("/actuator/metrics").header("Authorization", "Bearer "
                + TOKENS.user().groups(READERS_GROUP).build()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.names", hasItem("entra.security.jwt.authentications")))
                .andExpect(jsonPath("$.names", hasItem("entra.security.jwks.refreshes")));
    }

    @Test
    void graphLookupAndTokenAcquisitionAreMetered() throws Exception {
        String oid = UUID.randomUUID().toString();
        WIRE_MOCK.stubFor(WireMock.get(urlPathEqualTo("/v1.0/users/" + oid + "/transitiveMemberOf"))
                .willReturn(okJsonGroups()));
        long lookups = timerCount("entra.security.graph.lookups", "result", "success");
        long tokens = timerCount("entra.security.token.acquisitions", "result", "success", "credential",
                "client_secret");
        String token = TOKENS.user().claim("oid", oid)
                .claim("_claim_names", Map.of("groups", "src1"))
                .claim("_claim_sources", Map.of("src1", Map.of("endpoint", "https://graph.windows.net/x/getMemberObjects")))
                .build();

        mvc.perform(get("/orders").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/orders").header("Authorization", "Bearer " + token)).andExpect(status().isOk());

        assertThat(timerCount("entra.security.graph.lookups", "result", "success")).isEqualTo(lookups + 1);
        assertThat(timerCount("entra.security.token.acquisitions", "result", "success", "credential", "client_secret"))
                .isEqualTo(tokens + 1);
        assertThat(registry.find("entra.security.graph.lookups").tag("result", "success").timer().getId().getTags()
                .stream().noneMatch(tag -> oid.equals(tag.getValue()))).isTrue();
    }

    private double count(String result, String reason) {
        Counter counter = registry.find("entra.security.jwt.authentications").tag("result", result)
                .tag("reason", reason).counter();
        return counter == null ? 0 : counter.count();
    }

    private long timerCount(String name, String... tags) {
        Timer timer = registry.find(name).tags(tags).timer();
        return timer == null ? 0 : timer.count();
    }

    private static com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder okJsonGroups() {
        return com.github.tomakehurst.wiremock.client.WireMock.okJson("{\"value\":[{\"@odata.type\":"
                + "\"#microsoft.graph.group\",\"id\":\"" + READERS_GROUP + "\",\"displayName\":\"Overage Group\"}]}");
    }
}
