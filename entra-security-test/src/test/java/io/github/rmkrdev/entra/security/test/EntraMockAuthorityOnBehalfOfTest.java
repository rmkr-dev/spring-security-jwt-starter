package io.github.rmkrdev.entra.security.test;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.rmkrdev.entra.security.core.jwt.EntraJwtDecoders;

class EntraMockAuthorityOnBehalfOfTest {

    static final String TENANT = "11111111-1111-1111-1111-111111111111";
    static final String CLIENT = "22222222-2222-2222-2222-222222222222";
    static final String USER = "a0a0a0a0-0000-4000-8000-0000000000b1";

    static EntraMockAuthority authority;
    static EntraTestTokens tokens;
    static NimbusJwtDecoder downstreamDecoder;

    final HttpClient http = HttpClient.newHttpClient();
    final ObjectMapper json = new ObjectMapper();

    @BeforeAll
    static void start() {
        authority = EntraMockAuthority.start();
        tokens = authority.tokens(TENANT, CLIENT);
        downstreamDecoder = EntraJwtDecoders.create(
                EntraJwtDecoders.jwkSource(URI.create(authority.jwkSetUri(TENANT)), Duration.ofMinutes(5),
                        Duration.ofSeconds(5)),
                List.of(authority.issuer(TENANT)), List.of("api://downstream"), TENANT, Duration.ofSeconds(30));
    }

    @AfterAll
    static void stop() {
        authority.close();
    }

    @BeforeEach
    void reset() {
        authority.reset();
    }

    @Test
    void exchangesAUserTokenForADelegatedDownstreamTokenForTheSameUser() throws Exception {
        String incoming = tokens.user().objectId(USER).name("Alice").username("alice@contoso.example").build();

        HttpResponse<String> response = obo(incoming, "api://downstream/Data.Read api://downstream/Data.Write");

        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode body = json.readTree(response.body());
        assertThat(body.path("expires_in").asLong()).isEqualTo(3600);
        Jwt downstream = downstreamDecoder.decode(body.path("access_token").asText());
        assertThat(downstream.getAudience()).containsExactly("api://downstream");
        assertThat(downstream.getClaimAsString("oid")).isEqualTo(USER);
        assertThat(downstream.getClaimAsString("azp")).isEqualTo(CLIENT);
        assertThat(downstream.getClaimAsString("scp")).isEqualTo("Data.Read Data.Write");
        assertThat(downstream.getClaimAsString("name")).isEqualTo("Alice");
        assertThat(downstream.getClaimAsString("preferred_username")).isEqualTo("alice@contoso.example");
        assertThat(downstream.hasClaim("idtyp")).isFalse();

        assertThat(authority.onBehalfOfRequests()).isEqualTo(1);
        assertThat(authority.tokenRequests()).isEqualTo(1);
        Map<String, String> form = authority.onBehalfOfRequestForms().get(0);
        assertThat(form).containsEntry("assertion", "****").containsEntry("client_secret", "****")
                .containsEntry("client_id", CLIENT).containsEntry("requested_token_use", "on_behalf_of");
    }

    @Test
    void defaultScopeAndCustomLifetime() throws Exception {
        authority.onBehalfOfTokenLifetime(Duration.ofMinutes(2));

        HttpResponse<String> response = obo(tokens.user().build(), "api://downstream/.default");

        JsonNode body = json.readTree(response.body());
        assertThat(body.path("expires_in").asLong()).isEqualTo(120);
        assertThat(downstreamDecoder.decode(body.path("access_token").asText()).getClaimAsString("scp"))
                .isEqualTo("user_impersonation");
    }

    @Test
    void assertionsMustBeValidUserTokensForTheCallingClient() throws Exception {
        assertError(obo(authority.tokens(TENANT, "some-other-api").user().build(), "api://downstream/.default"),
                400, "invalid_grant", 50013);
        assertError(obo(tokens.service().build(), "api://downstream/.default"), 400, "invalid_grant", 50013);
        assertError(obo(tokens.user().signedWithUnknownKey().build(), "api://downstream/.default"), 400,
                "invalid_grant", 50013);
        assertError(obo(tokens.user().expired().build(), "api://downstream/.default"), 400, "invalid_grant", 500133);
        assertError(obo("not-a-jwt", "api://downstream/.default"), 400, "invalid_grant", 50013);
    }

    @Test
    void requestsMustAuthenticateTheClientAndAskForOnBehalfOf() throws Exception {
        String assertion = tokens.user().build();
        assertError(post("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&client_id=" + CLIENT
                + "&requested_token_use=on_behalf_of&scope=api%3A%2F%2Fd%2F.default&assertion=" + assertion),
                401, "invalid_client", 7000218);
        assertError(post("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&client_id=" + CLIENT
                + "&client_secret=s&scope=api%3A%2F%2Fd%2F.default&assertion=" + assertion),
                400, "invalid_request", 900144);
    }

    @Test
    void missingConsentIsReportedLikeEntra() throws Exception {
        authority.requireConsent("api://downstream");

        JsonNode error = assertError(obo(tokens.user().build(), "api://downstream/Data.Read"), 400, "invalid_grant",
                65001);
        assertThat(error.path("suberror").asText()).isEqualTo("consent_required");
        assertThat(error.path("error_description").asText()).startsWith("AADSTS65001");

        authority.reset();
        assertThat(obo(tokens.user().build(), "api://downstream/Data.Read").statusCode()).isEqualTo(200);
    }

    @Test
    void conditionalAccessChallengeIsReportedWithClaims() throws Exception {
        authority.requireInteraction("api://downstream/Data.Write", "{\"access_token\":{\"acrs\":{\"essential\":true,"
                + "\"value\":\"c1\"}}}");

        assertThat(obo(tokens.user().build(), "api://downstream/Data.Read").statusCode()).isEqualTo(200);
        JsonNode error = assertError(obo(tokens.user().build(), "api://downstream/Data.Write"), 400,
                "interaction_required", 50076);
        assertThat(error.path("claims").asText()).contains("\"acrs\"");
    }

    private JsonNode assertError(HttpResponse<String> response, int status, String error, int code) throws Exception {
        assertThat(response.statusCode()).isEqualTo(status);
        JsonNode body = json.readTree(response.body());
        assertThat(body.path("error").asText()).isEqualTo(error);
        assertThat(body.path("error_codes").get(0).asInt()).isEqualTo(code);
        return body;
    }

    private HttpResponse<String> obo(String assertion, String scope) throws Exception {
        return post("grant_type=" + enc("urn:ietf:params:oauth:grant-type:jwt-bearer") + "&client_id=" + CLIENT
                + "&client_secret=s&requested_token_use=on_behalf_of&scope=" + enc(scope) + "&assertion="
                + enc(assertion));
    }

    private HttpResponse<String> post(String form) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(authority.baseUrl() + "/" + TENANT
                + "/oauth2/v2.0/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
