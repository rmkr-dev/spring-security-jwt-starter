package io.github.rmkrdev.entra.security.autoconfigure.it;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
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
 * A B2C-style custom domain: only the host and the tenant path (directory and user flow) are configured, and
 * everything else comes from the OIDC discovery document.
 */
@SpringBootTest(properties = {
        "entra.security.authority.allow-http=true",
        "entra.security.authority.tenant-path=contoso.onmicrosoft.com/B2C_1_signin",
        "entra.security.authority.discovery.enabled=true",
        "entra.security.graph.overage-enabled=false" })
@AutoConfigureMockMvc
class EntraDiscoveryIntegrationTest {

    static final WireMockServer IDP = new WireMockServer(options().dynamicPort());
    static final String HOST;
    static final TestTokens TOKENS;
    static final String METADATA = "/contoso.onmicrosoft.com/B2C_1_signin/v2.0/.well-known/openid-configuration";
    static final String KEYS = "/contoso.onmicrosoft.com/b2c_1_signin/discovery/v2.0/keys";

    static {
        IDP.start();
        HOST = "http://idp.contoso.test:" + IDP.port();
        TOKENS = new TestTokens(HOST);
        IDP.stubFor(get(METADATA).willReturn(okJson("{\"issuer\":\"" + TOKENS.v2Issuer() + "\","
                + "\"jwks_uri\":\"" + HOST + KEYS + "\","
                + "\"token_endpoint\":\"" + HOST + "/contoso.onmicrosoft.com/b2c_1_signin/oauth2/v2.0/token\","
                + "\"authorization_endpoint\":\"" + HOST + "/contoso.onmicrosoft.com/b2c_1_signin/oauth2/v2.0/authorize\"}")));
        IDP.stubFor(get(KEYS).willReturn(okJson(TOKENS.jwksJson())));
        Runtime.getRuntime().addShutdownHook(new Thread(IDP::stop));
    }

    @DynamicPropertySource
    static void idp(DynamicPropertyRegistry registry) {
        registry.add("entra.security.authority.host", () -> HOST);
    }

    @Autowired
    MockMvc mvc;

    @Autowired
    EntraEndpoints endpoints;

    @Test
    void endpointsAreDiscovered() {
        assertThat(endpoints.isDiscovered()).isTrue();
        assertThat(endpoints.metadataUri()).hasToString(HOST + METADATA);
        assertThat(endpoints.issuers()).containsExactly(TOKENS.v2Issuer());
        assertThat(endpoints.jwksUri()).hasToString(HOST + KEYS);
        assertThat(endpoints.tokenEndpoint().getPath()).isEqualTo("/contoso.onmicrosoft.com/b2c_1_signin/oauth2/v2.0/token");
        assertThat(endpoints.authorizeEndpoint().getPath()).endsWith("/oauth2/v2.0/authorize");
        IDP.verify(getRequestedFor(urlPathEqualTo(METADATA))
                .withHeader("Host", equalTo("idp.contoso.test:" + IDP.port())));
    }

    @Test
    void tokenSignedWithTheDiscoveredKeysIsAccepted() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/me").header("Authorization", "Bearer " + TOKENS.user().build()))
                .andExpect(status().isOk());
    }

    @Test
    void onlyTheDiscoveredIssuerIsAccepted() throws Exception {
        String v1 = TOKENS.user().issuer(TestTokens.V1_ISSUER).build();
        mvc.perform(MockMvcRequestBuilders.get("/me").header("Authorization", "Bearer " + v1))
                .andExpect(status().isUnauthorized());
    }
}
