package io.github.rmkrdev.entra.security.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.rmkrdev.entra.security.core.jwt.EntraJwtDecoders;

class EntraMockAuthorityTest {

    static final String TENANT = "11111111-1111-1111-1111-111111111111";
    static final String CLIENT = "22222222-2222-2222-2222-222222222222";

    static EntraMockAuthority authority;
    static EntraTestTokens tokens;
    static NimbusJwtDecoder decoder;

    final HttpClient http = HttpClient.newHttpClient();
    final ObjectMapper json = new ObjectMapper();

    @BeforeAll
    static void start() {
        authority = EntraMockAuthority.start();
        tokens = authority.tokens(TENANT, CLIENT);
        decoder = EntraJwtDecoders.create(
                EntraJwtDecoders.jwkSource(URI.create(authority.jwkSetUri(TENANT)), Duration.ofMinutes(5),
                        Duration.ofSeconds(5)),
                List.of(authority.issuer(TENANT), "https://sts.windows.net/" + TENANT + "/"),
                List.of(CLIENT, "api://" + CLIENT), TENANT, Duration.ofSeconds(30));
    }

    @AfterAll
    static void stop() {
        authority.close();
    }

    @Test
    void servesJwksForAnyTenant() throws Exception {
        HttpResponse<String> response = get("/" + TENANT + "/discovery/v2.0/keys");
        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode keys = json.readTree(response.body()).path("keys");
        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).path("kty").asText()).isEqualTo("RSA");
        assertThat(keys.get(0).has("d")).as("private part must never be published").isFalse();
        assertThat(get("/contoso.onmicrosoft.com/discovery/keys").statusCode()).isEqualTo(200);
    }

    @Test
    void servesDiscoveryDocument() throws Exception {
        JsonNode doc = json.readTree(get("/" + TENANT + "/v2.0/.well-known/openid-configuration").body());
        assertThat(doc.path("issuer").asText()).isEqualTo(authority.issuer(TENANT));
        assertThat(doc.path("jwks_uri").asText()).isEqualTo(authority.jwkSetUri(TENANT));
    }

    @Test
    void userTokensValidateWithTheStarterDecoder() {
        Jwt jwt = decoder.decode(tokens.user().groups("g1", "g2").appRoles("Reader").build());
        assertThat(jwt.getClaimAsString("iss")).isEqualTo(authority.issuer(TENANT));
        assertThat(jwt.getAudience()).containsExactly(CLIENT);
        assertThat(jwt.getClaimAsString("tid")).isEqualTo(TENANT);
        assertThat(jwt.getClaimAsString("scp")).isEqualTo("access_as_user");
        assertThat(jwt.getClaimAsStringList("groups")).containsExactly("g1", "g2");
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("Reader");
        assertThat(jwt.getClaimAsString("azp")).isEqualTo(EntraTestTokens.USER_CLIENT_APP_ID);
        assertThat(jwt.hasClaim("idtyp")).isFalse();
    }

    @Test
    void v1TokensUseV1Claims() {
        Jwt jwt = decoder.decode(tokens.user().v1().build());
        assertThat(jwt.getClaimAsString("iss")).isEqualTo("https://sts.windows.net/" + TENANT + "/");
        assertThat(jwt.getAudience()).containsExactly("api://" + CLIENT);
        assertThat(jwt.getClaimAsString("appid")).isEqualTo(EntraTestTokens.USER_CLIENT_APP_ID);
        assertThat(jwt.getClaimAsString("upn")).isEqualTo("test.user@contoso.example");
        assertThat(jwt.hasClaim("azp")).isFalse();
        assertThat(jwt.getClaimAsString("ver")).isEqualTo("1.0");
    }

    @Test
    void serviceTokensAreAppOnly() {
        Jwt jwt = decoder.decode(tokens.service().appRoles("Orders.Sync").build());
        assertThat(jwt.getClaimAsString("idtyp")).isEqualTo("app");
        assertThat(jwt.hasClaim("scp")).isFalse();
        assertThat(jwt.getClaimAsString("azp")).isEqualTo(EntraTestTokens.SERVICE_APP_ID);
        assertThat(jwt.getClaimAsString("oid")).isEqualTo(EntraTestTokens.SERVICE_OBJECT_ID);
    }

    @Test
    void groupOverageReplacesGroups() {
        Jwt jwt = decoder.decode(tokens.user().groups("g1").groupOverage().build());
        assertThat(jwt.hasClaim("groups")).isFalse();
        assertThat(jwt.getClaimAsMap("_claim_names")).containsEntry("groups", "src1");
    }

    @Test
    void badTokensAreRejected() {
        assertThatThrownBy(() -> decoder.decode(tokens.user().expired().build())).isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> decoder.decode(tokens.user().signedWithUnknownKey().build()))
                .isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> decoder.decode(tokens.user().signedWithHmac().build()))
                .isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> decoder.decode(tokens.user().without("aud").build()))
                .isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> decoder.decode(tokens.user().issuer("https://evil.example/").build()))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void tokenEndpointIssuesAppOnlyTokens() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(authority.baseUrl() + "/" + TENANT + "/oauth2/v2.0/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials&client_id=caller-app"
                        + "&client_secret=s&scope=" + CLIENT + "%2F.default"))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode body = json.readTree(response.body());
        assertThat(body.path("token_type").asText()).isEqualTo("Bearer");
        Jwt jwt = decoder.decode(body.path("access_token").asText());
        assertThat(jwt.getClaimAsString("azp")).isEqualTo("caller-app");
        assertThat(jwt.getAudience()).containsExactly(CLIENT);
    }

    @Test
    void tokenEndpointRejectsOtherGrants() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(authority.baseUrl() + "/" + TENANT + "/oauth2/v2.0/token"))
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=password&username=u&password=p"))
                .build();
        assertThat(http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(400);
    }

    @Test
    void graphRequiresBearerAndReturnsRegisteredGroups() throws Exception {
        authority.registerGroups("OID-1", "g1", "g2");
        HttpRequest anonymous = HttpRequest.newBuilder(URI.create(authority.baseUrl() + "/v1.0/users/oid-1/transitiveMemberOf"))
                .GET().build();
        assertThat(http.send(anonymous, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);

        HttpRequest authorized = HttpRequest.newBuilder(URI.create(authority.baseUrl()
                + "/v1.0/users/oid-1/transitiveMemberOf?$select=id,displayName"))
                .header("Authorization", "Bearer x").GET().build();
        JsonNode value = json.readTree(http.send(authorized, HttpResponse.BodyHandlers.ofString()).body()).path("value");
        assertThat(value).hasSize(2);
        assertThat(value.get(0).path("id").asText()).isEqualTo("g1");
    }

    @Test
    void unknownPathsAre404() throws Exception {
        assertThat(get("/nope").statusCode()).isEqualTo(404);
    }

    @Test
    void tokensNeedTenantAndClient() {
        assertThatThrownBy(() -> authority.tokens(" ", CLIENT)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> authority.tokens(TENANT, null)).isInstanceOf(IllegalArgumentException.class);
    }

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(authority.baseUrl() + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
