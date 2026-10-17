package io.github.rmkrdev.entra.security.support;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

import org.springframework.test.context.DynamicPropertyRegistry;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.core.test.TestTokens;

/**
 * A single WireMock server standing in for Entra (JWKS + token endpoint) and Microsoft Graph,
 * shared by the integration tests of this module.
 */
public final class EntraTestServer {

    public static final WireMockServer WIRE_MOCK = new WireMockServer(options().dynamicPort());
    public static final TestTokens TOKENS;

    static {
        WIRE_MOCK.start();
        TOKENS = new TestTokens(WIRE_MOCK.baseUrl());
        WIRE_MOCK.stubFor(get("/" + TestTokens.TENANT_ID + "/discovery/v2.0/keys")
                .willReturn(okJson(TOKENS.jwksJson())));
        WIRE_MOCK.stubFor(post("/" + TestTokens.TENANT_ID + "/oauth2/v2.0/token")
                .willReturn(okJson("{\"token_type\":\"Bearer\",\"expires_in\":3600,\"access_token\":\"app-token\"}")));
        Runtime.getRuntime().addShutdownHook(new Thread(WIRE_MOCK::stop));
    }

    private EntraTestServer() {
    }

    public static void register(DynamicPropertyRegistry registry) {
        registry.add("entra.security.authority-host", WIRE_MOCK::baseUrl);
        registry.add("entra.security.graph.base-url", WIRE_MOCK::baseUrl);
    }
}
