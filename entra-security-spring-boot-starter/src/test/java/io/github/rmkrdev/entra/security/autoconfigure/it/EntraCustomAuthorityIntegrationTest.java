package io.github.rmkrdev.entra.security.autoconfigure.it;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.autoconfigure.EntraEndpoints;
import io.github.rmkrdev.entra.security.core.test.TestTokens;

/**
 * A sovereign-cloud style deployment: the authority and Graph live on custom host names (resolved to a local
 * mock through the test hosts file), configured only through {@code entra.security.authority.*}.
 */
@SpringBootTest(properties = {
        "entra.security.authority.allow-http=true",
        "entra.security.graph.overage-enabled=true" })
@AutoConfigureMockMvc
class EntraCustomAuthorityIntegrationTest {

    static final WireMockServer AUTHORITY = new WireMockServer(options().dynamicPort());
    static final TestTokens TOKENS;
    static final String LOGIN_HOST;
    static final String GRAPH_HOST;

    static {
        AUTHORITY.start();
        LOGIN_HOST = "http://login.sovereign.test:" + AUTHORITY.port();
        GRAPH_HOST = "http://graph.sovereign.test:" + AUTHORITY.port();
        TOKENS = new TestTokens(LOGIN_HOST);
        AUTHORITY.stubFor(get("/" + TestTokens.TENANT_ID + "/discovery/v2.0/keys")
                .willReturn(okJson(TOKENS.jwksJson())));
        AUTHORITY.stubFor(post("/" + TestTokens.TENANT_ID + "/oauth2/v2.0/token")
                .willReturn(okJson("{\"token_type\":\"Bearer\",\"expires_in\":3600,\"access_token\":\"gov-app\"}")));
        AUTHORITY.stubFor(get(urlPathEqualTo("/v1.0/users/" + TestTokens.USER_OID + "/transitiveMemberOf"))
                .willReturn(okJson("{\"value\":[{\"@odata.type\":\"#microsoft.graph.group\","
                        + "\"id\":\"aaaaaaaa-0000-0000-0000-000000000001\",\"displayName\":\"Readers\"}]}")));
        Runtime.getRuntime().addShutdownHook(new Thread(AUTHORITY::stop));
    }

    @DynamicPropertySource
    static void authority(DynamicPropertyRegistry registry) {
        registry.add("entra.security.authority.host", () -> LOGIN_HOST);
        registry.add("entra.security.authority.graph-base-url", () -> GRAPH_HOST);
    }

    @Autowired
    MockMvc mvc;

    @Autowired
    EntraEndpoints endpoints;

    @Test
    void endpointsComeFromTheCustomHost() {
        assertThat(endpoints.jwksUri()).hasToString(LOGIN_HOST + "/" + TestTokens.TENANT_ID + "/discovery/v2.0/keys");
        assertThat(endpoints.tokenEndpoint()).hasToString(LOGIN_HOST + "/" + TestTokens.TENANT_ID + "/oauth2/v2.0/token");
        assertThat(endpoints.issuers()).contains(LOGIN_HOST + "/" + TestTokens.TENANT_ID + "/v2.0");
        assertThat(endpoints.graphBaseUrl()).hasToString(GRAPH_HOST);
    }

    @Test
    void tokenFromTheCustomAuthorityIsAccepted() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/orders")
                .header("Authorization", "Bearer " + TOKENS.user().groups("aaaaaaaa-0000-0000-0000-000000000001").build()))
                .andExpect(status().isOk())
                .andExpect(content().string("orders"));
        AUTHORITY.verify(getRequestedFor(urlPathEqualTo("/" + TestTokens.TENANT_ID + "/discovery/v2.0/keys"))
                .withHeader("Host", equalTo("login.sovereign.test:" + AUTHORITY.port())));
    }

    @Test
    void tokenFromThePublicCloudIssuerIsRejected() throws Exception {
        String publicCloud = TOKENS.user().issuer("https://login.microsoftonline.com/" + TestTokens.TENANT_ID + "/v2.0")
                .groups("aaaaaaaa-0000-0000-0000-000000000001").build();
        mvc.perform(MockMvcRequestBuilders.get("/orders").header("Authorization", "Bearer " + publicCloud))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void groupOverageUsesTheCustomTokenEndpointAndGraphHost() throws Exception {
        String overage = TOKENS.user().claim("_claim_names", java.util.Map.of("groups", "src1")).build();
        mvc.perform(MockMvcRequestBuilders.get("/orders").header("Authorization", "Bearer " + overage))
                .andExpect(status().isOk());
        AUTHORITY.verify(postRequestedFor(urlPathEqualTo("/" + TestTokens.TENANT_ID + "/oauth2/v2.0/token"))
                .withHeader("Host", equalTo("login.sovereign.test:" + AUTHORITY.port())));
        AUTHORITY.verify(getRequestedFor(urlPathEqualTo("/v1.0/users/" + TestTokens.USER_OID + "/transitiveMemberOf"))
                .withHeader("Host", equalTo("graph.sovereign.test:" + AUTHORITY.port()))
                .withHeader("Authorization", equalTo("Bearer gov-app")));
    }
}
