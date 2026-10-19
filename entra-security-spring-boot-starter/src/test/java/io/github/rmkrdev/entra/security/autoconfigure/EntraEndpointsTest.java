package io.github.rmkrdev.entra.security.autoconfigure;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.net.URI;
import java.time.Clock;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.web.client.RestClient;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.CredentialType;
import io.github.rmkrdev.entra.security.core.token.ClientCredentialsTokenProvider;

class EntraEndpointsTest {

    static final String TENANT = "11111111-1111-1111-1111-111111111111";
    static final WireMockServer WIRE_MOCK = new WireMockServer(options().dynamicPort());

    EntraSecurityProperties properties;

    @BeforeAll
    static void start() {
        WIRE_MOCK.start();
    }

    @AfterAll
    static void stop() {
        WIRE_MOCK.stop();
    }

    @BeforeEach
    void setUp() {
        WIRE_MOCK.resetAll();
        properties = new EntraSecurityProperties();
        properties.setTenantId(TENANT);
        properties.setClientId("22222222-2222-2222-2222-222222222222");
    }

    @Test
    void defaultsAreTheEntraPublicCloudEndpoints() {
        EntraEndpoints endpoints = EntraEndpoints.resolve(properties, RestClient.create());

        assertThat(endpoints.authorityHost()).hasToString("https://login.microsoftonline.com");
        assertThat(endpoints.tenantPath()).isEqualTo(TENANT);
        assertThat(endpoints.issuers()).containsExactly("https://login.microsoftonline.com/" + TENANT + "/v2.0",
                "https://sts.windows.net/" + TENANT + "/");
        assertThat(endpoints.jwksUri())
                .hasToString("https://login.microsoftonline.com/" + TENANT + "/discovery/v2.0/keys");
        assertThat(endpoints.tokenEndpoint())
                .hasToString("https://login.microsoftonline.com/" + TENANT + "/oauth2/v2.0/token");
        assertThat(endpoints.authorizeEndpoint())
                .hasToString("https://login.microsoftonline.com/" + TENANT + "/oauth2/v2.0/authorize");
        assertThat(endpoints.userinfoEndpoint()).hasToString("https://graph.microsoft.com/oidc/userinfo");
        assertThat(endpoints.graphBaseUrl()).hasToString("https://graph.microsoft.com");
        assertThat(endpoints.isTokenEndpointCustomized()).isFalse();
        assertThat(endpoints.isDiscovered()).isFalse();
        assertThat(endpoints.metadataUri()).isNull();
        assertThat(endpoints.metadata("issuer")).isNull();
        assertThat(endpoints.toString()).contains("login.microsoftonline.com").doesNotContain("metadataUri");
    }

    @Test
    void sovereignCloudHostMovesEveryDerivedEndpoint() {
        properties.getAuthority().setHost(URI.create("https://login.microsoftonline.us/"));
        properties.getAuthority().setGraphBaseUrl(URI.create("https://graph.microsoft.us"));

        EntraEndpoints endpoints = EntraEndpoints.of(properties);

        assertThat(endpoints.issuers()).first().isEqualTo("https://login.microsoftonline.us/" + TENANT + "/v2.0");
        assertThat(endpoints.jwksUri())
                .hasToString("https://login.microsoftonline.us/" + TENANT + "/discovery/v2.0/keys");
        assertThat(endpoints.tokenEndpoint())
                .hasToString("https://login.microsoftonline.us/" + TENANT + "/oauth2/v2.0/token");
        assertThat(endpoints.graphBaseUrl()).hasToString("https://graph.microsoft.us");
        assertThat(endpoints.userinfoEndpoint()).hasToString("https://graph.microsoft.us/oidc/userinfo");
    }

    @Test
    void authorityOverridesWinOverTheOlderTopLevelProperties() {
        properties.setAuthorityHost(URI.create("https://legacy.example"));
        properties.setJwkSetUri(URI.create("https://legacy.example/keys"));
        properties.setIssuers(List.of("https://legacy.example/issuer"));
        assertThat(EntraEndpoints.of(properties).jwksUri()).hasToString("https://legacy.example/keys");
        assertThat(EntraEndpoints.of(properties).issuers()).containsExactly("https://legacy.example/issuer");
        assertThat(EntraEndpoints.of(properties).tokenEndpoint())
                .hasToString("https://legacy.example/" + TENANT + "/oauth2/v2.0/token");

        EntraSecurityProperties.Authority authority = properties.getAuthority();
        authority.setHost(URI.create("https://login.contoso.com"));
        authority.setJwksUri(URI.create("https://keys.contoso.com/jwks"));
        authority.setIssuers(List.of("https://login.contoso.com/issuer"));
        authority.setTokenEndpoint(URI.create("https://login.contoso.com/token"));
        authority.setAuthorizeEndpoint(URI.create("https://login.contoso.com/authorize"));
        authority.setUserinfoEndpoint(URI.create("https://login.contoso.com/userinfo"));

        EntraEndpoints endpoints = EntraEndpoints.of(properties);
        assertThat(endpoints.authorityHost()).hasToString("https://login.contoso.com");
        assertThat(endpoints.jwksUri()).hasToString("https://keys.contoso.com/jwks");
        assertThat(endpoints.issuers()).containsExactly("https://login.contoso.com/issuer");
        assertThat(endpoints.tokenEndpoint()).hasToString("https://login.contoso.com/token");
        assertThat(endpoints.isTokenEndpointCustomized()).isTrue();
        assertThat(endpoints.authorizeEndpoint()).hasToString("https://login.contoso.com/authorize");
        assertThat(endpoints.userinfoEndpoint()).hasToString("https://login.contoso.com/userinfo");
    }

    @Test
    void tenantPathBuildsB2cStyleEndpoints() {
        properties.getAuthority().setHost(URI.create("https://contoso.b2clogin.com"));
        properties.getAuthority().setTenantPath("/contoso.onmicrosoft.com/B2C_1_signin/");

        EntraEndpoints endpoints = EntraEndpoints.of(properties);

        assertThat(endpoints.tenantPath()).isEqualTo("contoso.onmicrosoft.com/B2C_1_signin");
        assertThat(endpoints.jwksUri()).hasToString(
                "https://contoso.b2clogin.com/contoso.onmicrosoft.com/B2C_1_signin/discovery/v2.0/keys");
        assertThat(properties.resolveMetadataUri()).hasToString("https://contoso.b2clogin.com/"
                + "contoso.onmicrosoft.com/B2C_1_signin/v2.0/.well-known/openid-configuration");
        // Issuers always carry the tenant GUID, not the path.
        assertThat(endpoints.issuers()).first().isEqualTo("https://contoso.b2clogin.com/" + TENANT + "/v2.0");
    }

    @Test
    void discoveryFillsWhatIsNotConfigured() {
        String base = WIRE_MOCK.baseUrl();
        WIRE_MOCK.stubFor(get("/custom/.well-known/openid-configuration").willReturn(okJson("{"
                + "\"issuer\":\"https://idp.contoso.com/{tenantid}/v2.0\","
                + "\"jwks_uri\":\"" + base + "/custom/keys\","
                + "\"token_endpoint\":\"" + base + "/custom/token\","
                + "\"authorization_endpoint\":\"" + base + "/custom/authorize\","
                + "\"userinfo_endpoint\":\"" + base + "/custom/userinfo\","
                + "\"introspection_endpoint\":\"" + base + "/custom/introspect\","
                + "\"scopes_supported\":[\"openid\"]}")));
        properties.getAuthority().setMetadataUri(URI.create(base + "/custom/.well-known/openid-configuration"));
        properties.getAuthority().setAuthorizeEndpoint(URI.create("https://explicit.example/authorize"));

        EntraEndpoints endpoints = EntraEndpoints.resolve(properties, RestClient.create());

        assertThat(endpoints.isDiscovered()).isTrue();
        assertThat(endpoints.metadataUri()).hasToString(base + "/custom/.well-known/openid-configuration");
        assertThat(endpoints.issuers()).containsExactly("https://idp.contoso.com/" + TENANT + "/v2.0");
        assertThat(endpoints.jwksUri()).hasToString(base + "/custom/keys");
        assertThat(endpoints.tokenEndpoint()).hasToString(base + "/custom/token");
        assertThat(endpoints.isTokenEndpointCustomized()).isTrue();
        assertThat(endpoints.authorizeEndpoint()).hasToString("https://explicit.example/authorize");
        assertThat(endpoints.userinfoEndpoint()).hasToString(base + "/custom/userinfo");
        assertThat(endpoints.metadata("introspection_endpoint")).isEqualTo(base + "/custom/introspect");
        assertThat(endpoints.metadata("scopes_supported")).isNull();
        assertThat(endpoints.toString()).contains("metadataUri=");
    }

    @Test
    void explicitValuesWinOverDiscoveredOnes() {
        WIRE_MOCK.stubFor(get("/" + TENANT + "/v2.0/.well-known/openid-configuration").willReturn(okJson(
                "{\"issuer\":\"https://discovered/issuer\",\"jwks_uri\":\"https://discovered/keys\","
                        + "\"token_endpoint\":\"https://discovered/token\"}")));
        properties.getAuthority().setHost(URI.create(WIRE_MOCK.baseUrl()));
        properties.getAuthority().getDiscovery().setEnabled(true);
        properties.getAuthority().setIssuers(List.of("https://explicit/issuer"));
        properties.getAuthority().setJwksUri(URI.create("https://explicit/keys"));
        properties.getAuthority().setTokenEndpoint(URI.create("https://explicit/token"));

        EntraEndpoints endpoints = EntraEndpoints.resolve(properties, RestClient.create());

        assertThat(endpoints.isDiscovered()).isTrue();
        assertThat(endpoints.issuers()).containsExactly("https://explicit/issuer");
        assertThat(endpoints.jwksUri()).hasToString("https://explicit/keys");
        assertThat(endpoints.tokenEndpoint()).hasToString("https://explicit/token");
    }

    @Test
    void requiredDiscoveryFailsStartupWithTheUrl() {
        WIRE_MOCK.stubFor(get("/missing").willReturn(aResponse().withStatus(404)));
        properties.getAuthority().setMetadataUri(URI.create(WIRE_MOCK.baseUrl() + "/missing"));

        assertThatIllegalStateException().isThrownBy(() -> EntraEndpoints.resolve(properties, RestClient.create()))
                .withMessageContaining("OIDC discovery from " + WIRE_MOCK.baseUrl() + "/missing failed")
                .withMessageContaining("metadata-uri");
    }

    @Test
    void optionalDiscoveryFallsBackToTheDefaults() {
        WIRE_MOCK.stubFor(get("/broken").willReturn(okJson("[1,2]")));
        properties.getAuthority().setMetadataUri(URI.create(WIRE_MOCK.baseUrl() + "/broken"));
        properties.getAuthority().getDiscovery().setRequired(false);

        EntraEndpoints endpoints = EntraEndpoints.resolve(properties, RestClient.create());

        assertThat(endpoints.isDiscovered()).isFalse();
        assertThat(endpoints.jwksUri())
                .hasToString("https://login.microsoftonline.com/" + TENANT + "/discovery/v2.0/keys");
    }

    @Test
    void invalidDocumentsAreRejected() {
        assertDiscoveryFails("{\"jwks_uri\":\"https://x/keys\"}", "no issuer");
        assertDiscoveryFails("{\"issuer\":\" \",\"jwks_uri\":\"https://x/keys\"}", "no issuer");
        assertDiscoveryFails("{\"issuer\":\"https://x\"}", "no jwks_uri");
        assertDiscoveryFails("{\"issuer\":\"https://x\",\"jwks_uri\":\"http://idp.example/keys\"}",
                "jwks_uri 'http://idp.example/keys' uses http");
        assertDiscoveryFails("{\"issuer\":\"https://x\",\"jwks_uri\":\"https://x/keys\","
                + "\"token_endpoint\":\"ftp://x/token\"}", "token_endpoint 'ftp://x/token' must use https");
        assertDiscoveryFails("{\"issuer\":\"https://x\",\"jwks_uri\":\"https://x/keys\","
                + "\"userinfo_endpoint\":\"not a url\"}", "userinfo_endpoint is not a valid URL");
        assertDiscoveryFails("{\"issuer\":\"https://x\",\"jwks_uri\":\"/relative\"}", "must be an absolute");
    }

    @Test
    void missingJwksUriIsFineWhenItIsConfigured() {
        WIRE_MOCK.stubFor(get("/doc").willReturn(okJson("{\"issuer\":\"https://x\"}")));
        properties.getAuthority().setMetadataUri(URI.create(WIRE_MOCK.baseUrl() + "/doc"));
        properties.setJwkSetUri(URI.create("https://configured/keys"));

        EntraEndpoints endpoints = EntraEndpoints.resolve(properties, RestClient.create());

        assertThat(endpoints.jwksUri()).hasToString("https://configured/keys");
        assertThat(endpoints.issuers()).containsExactly("https://x");
        assertThat(endpoints.isTokenEndpointCustomized()).isFalse();
    }

    @Test
    void allowHttpAcceptsPlainHttpInClusterIdps() {
        WIRE_MOCK.stubFor(get("/doc").willReturn(okJson(
                "{\"issuer\":\"http://idp.auth.svc.cluster.local\",\"jwks_uri\":\"http://idp.auth.svc.cluster.local/k\"}")));
        properties.getAuthority().setMetadataUri(URI.create(WIRE_MOCK.baseUrl() + "/doc"));
        properties.getAuthority().setAllowHttp(true);

        assertThat(EntraEndpoints.resolve(properties, RestClient.create()).jwksUri())
                .hasToString("http://idp.auth.svc.cluster.local/k");
    }

    @Test
    void tokenProvidersUseTheResolvedTokenEndpoint() {
        properties.getCredential().setType(CredentialType.CLIENT_SECRET);
        properties.getCredential().setClientSecret("s");
        properties.getAuthority().setTokenEndpoint(URI.create("https://login.contoso.com/oauth2/token"));
        MockEnvironment environment = new MockEnvironment();

        EntraTokenProviders providers = new EntraTokenProviders(properties, environment, RestClient.create(),
                Clock.systemUTC(), null, null, EntraEndpoints.of(properties));

        assertThat(endpointOf(providers.applicationTokenProvider()))
                .hasToString("https://login.contoso.com/oauth2/token");

        // A credential in another tenant gets that tenant's endpoint on the authority host.
        EntraSecurityProperties.Credential other = new EntraSecurityProperties.Credential();
        other.setType(CredentialType.CLIENT_SECRET);
        other.setClientSecret("s");
        other.setTenantId("99999999-9999-9999-9999-999999999999");
        assertThat(endpointOf(providers.create(other))).hasToString(
                "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/oauth2/v2.0/token");
    }

    @Test
    void workloadIdentityKeepsAzureAuthorityHostUnlessTheHostIsConfigured() throws Exception {
        java.nio.file.Path tokenFile = java.nio.file.Files.createTempFile("federated", ".jwt");
        properties.getCredential().setType(CredentialType.WORKLOAD_IDENTITY);
        properties.getCredential().setFederatedTokenFile(tokenFile.toString());
        MockEnvironment environment = new MockEnvironment()
                .withProperty("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.us/");

        EntraTokenProviders providers = new EntraTokenProviders(properties, environment, RestClient.create(),
                Clock.systemUTC(), null, null, null);
        assertThat(endpointOf(providers.applicationTokenProvider()))
                .hasToString("https://login.microsoftonline.us/" + TENANT + "/oauth2/v2.0/token");

        properties.getAuthority().setHost(URI.create("https://login.sovereign.example"));
        providers = new EntraTokenProviders(properties, environment, RestClient.create(), Clock.systemUTC(), null,
                null, EntraEndpoints.of(properties));
        assertThat(endpointOf(providers.applicationTokenProvider()))
                .hasToString("https://login.sovereign.example/" + TENANT + "/oauth2/v2.0/token");
        java.nio.file.Files.deleteIfExists(tokenFile);
    }

    private static URI endpointOf(io.github.rmkrdev.entra.security.core.token.EntraTokenProvider provider) {
        return ((ClientCredentialsTokenProvider) provider).getTokenEndpoint();
    }

    private void assertDiscoveryFails(String document, String message) {
        WIRE_MOCK.stubFor(get("/doc").willReturn(okJson(document)));
        properties.getAuthority().setMetadataUri(URI.create(WIRE_MOCK.baseUrl() + "/doc"));
        assertThatIllegalStateException().isThrownBy(() -> EntraEndpoints.resolve(properties, RestClient.create()))
                .withMessageContaining(message);
    }
}
