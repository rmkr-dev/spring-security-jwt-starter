package io.github.rmkrdev.entra.security.core.introspect;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import com.github.tomakehurst.wiremock.WireMockServer;

class TokenIntrospectorsTest {

    static final WireMockServer SERVER = new WireMockServer(options().dynamicPort());

    RestClient rest = RestClient.create();

    @BeforeAll
    static void start() {
        SERVER.start();
    }

    @AfterAll
    static void stop() {
        SERVER.stop();
    }

    @BeforeEach
    void reset() {
        SERVER.resetAll();
    }

    URI uri(String path) {
        return URI.create(SERVER.baseUrl() + path);
    }

    @Test
    void activeResponseKeepsTheClaimsWithoutActive() {
        SERVER.stubFor(post("/introspect").willReturn(okJson("{\"active\":true,\"sub\":\"s\",\"scope\":\"a b\"}")));
        Rfc7662TokenIntrospector introspector = new Rfc7662TokenIntrospector(rest, uri("/introspect"),
                IntrospectionClientAuthentication.clientSecretBasic("api client", "p@ss:word"), "access_token");

        IntrospectionResult result = introspector.introspect("tok");

        assertThat(result.active()).isTrue();
        assertThat(result.claims()).containsEntry("sub", "s").doesNotContainKey("active");
        assertThat(introspector.getEndpoint()).isEqualTo(uri("/introspect"));
        // RFC 6749 2.3.1: id and secret are form-urlencoded before Base64.
        String expected = "Basic " + java.util.Base64.getEncoder()
                .encodeToString("api+client:p%40ss%3Aword".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        SERVER.verify(postRequestedFor(urlEqualTo("/introspect"))
                .withHeader("Authorization", equalTo(expected))
                .withRequestBody(containing("token=tok"))
                .withRequestBody(containing("token_type_hint=access_token")));
    }

    @Test
    void inactiveOrMissingActiveIsInactive() {
        SERVER.stubFor(post("/introspect").willReturn(okJson("{\"active\":false}")));
        Rfc7662TokenIntrospector introspector = new Rfc7662TokenIntrospector(rest, uri("/introspect"),
                IntrospectionClientAuthentication.clientSecretPost("id", "secret"), null);
        assertThat(introspector.introspect("tok").active()).isFalse();
        SERVER.verify(postRequestedFor(urlEqualTo("/introspect"))
                .withHeader("Authorization", absent())
                .withRequestBody(containing("client_id=id"))
                .withRequestBody(containing("client_secret=secret")));

        SERVER.stubFor(post("/introspect").willReturn(okJson("{\"active\":\"true\"}")));
        assertThat(introspector.introspect("tok")).isEqualTo(IntrospectionResult.inactive());
    }

    @Test
    void bearerAndNoneAuthentication() {
        SERVER.stubFor(post("/introspect").willReturn(okJson("{\"active\":true,\"sub\":\"x\"}")));
        new Rfc7662TokenIntrospector(rest, uri("/introspect"), IntrospectionClientAuthentication.bearer(() -> "app"),
                " ").introspect("tok");
        SERVER.verify(postRequestedFor(urlEqualTo("/introspect")).withHeader("Authorization", equalTo("Bearer app")));

        SERVER.resetRequests();
        new Rfc7662TokenIntrospector(rest, uri("/introspect"), IntrospectionClientAuthentication.none(), null)
                .introspect("tok");
        SERVER.verify(postRequestedFor(urlEqualTo("/introspect")).withHeader("Authorization", absent())
                .withRequestBody(equalTo("token=tok")));
    }

    @Test
    void errorsAreIntrospectionExceptions() {
        Rfc7662TokenIntrospector introspector = new Rfc7662TokenIntrospector(rest, uri("/introspect"),
                IntrospectionClientAuthentication.none(), null);
        SERVER.stubFor(post("/introspect").willReturn(aResponse().withStatus(401)));
        assertThatThrownBy(() -> introspector.introspect("tok")).isInstanceOf(IntrospectionException.class)
                .hasMessageContaining("/introspect");
        SERVER.stubFor(post("/introspect").willReturn(aResponse().withStatus(503)));
        assertThatThrownBy(() -> introspector.introspect("tok")).isInstanceOf(IntrospectionException.class);
        SERVER.stubFor(post("/introspect").willReturn(aResponse().withStatus(200)));
        assertThatThrownBy(() -> introspector.introspect("tok")).isInstanceOf(IntrospectionException.class)
                .hasMessageContaining("no body");
    }

    @Test
    void userInfoAnswers() {
        UserInfoTokenIntrospector introspector = new UserInfoTokenIntrospector(rest, uri("/me"));
        assertThat(introspector.getEndpoint()).isEqualTo(uri("/me"));

        SERVER.stubFor(get("/me").withHeader("Authorization", equalTo("Bearer graph-token"))
                .willReturn(okJson("{\"id\":\"oid-1\",\"displayName\":\"Name\"}")));
        IntrospectionResult result = introspector.introspect("graph-token");
        assertThat(result.active()).isTrue();
        assertThat(result.claims()).containsEntry("id", "oid-1");

        SERVER.stubFor(get("/me").willReturn(aResponse().withStatus(401)));
        assertThat(introspector.introspect("other").active()).isFalse();
        SERVER.stubFor(get("/me").willReturn(aResponse().withStatus(403)));
        assertThat(introspector.introspect("other").active()).isFalse();
        SERVER.stubFor(get("/me").willReturn(aResponse().withStatus(429)));
        assertThatThrownBy(() -> introspector.introspect("other")).isInstanceOf(IntrospectionException.class);
        SERVER.stubFor(get("/me").willReturn(aResponse().withStatus(500)));
        assertThatThrownBy(() -> introspector.introspect("other")).isInstanceOf(IntrospectionException.class);
        SERVER.stubFor(get("/me").willReturn(aResponse().withStatus(200)));
        assertThatThrownBy(() -> introspector.introspect("other")).hasMessageContaining("no body");
    }

    @Test
    void resultsCopyTheirClaims() {
        assertThat(new IntrospectionResult(true, null).claims()).isEmpty();
        assertThat(IntrospectionResult.active(java.util.Map.of("a", 1)).claims()).containsEntry("a", 1);
    }
}
