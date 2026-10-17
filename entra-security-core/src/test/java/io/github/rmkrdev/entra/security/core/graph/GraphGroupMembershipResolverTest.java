package io.github.rmkrdev.entra.security.core.graph;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.core.token.AccessToken;

class GraphGroupMembershipResolverTest {

    private static final String OID = "33333333-3333-3333-3333-333333333333";
    private static final String PATH = "/v1.0/users/" + OID + "/transitiveMemberOf";

    private WireMockServer wireMock;
    private GraphGroupMembershipResolver resolver;

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        resolver = new GraphGroupMembershipResolver(RestClient.create(),
                scope -> new AccessToken("graph-token", Instant.now().plusSeconds(3600)),
                URI.create(wireMock.baseUrl() + "/"), "https://graph.microsoft.com/.default", 5);
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    @Test
    void followsPagingAndKeepsOnlyGroups() {
        wireMock.stubFor(get(urlPathEqualTo(PATH)).withQueryParam("$select", equalTo("id,displayName"))
                .willReturn(okJson("{\"value\":[{\"@odata.type\":\"#microsoft.graph.group\",\"id\":\"g1\","
                        + "\"displayName\":\"Readers\"},{\"@odata.type\":\"#microsoft.graph.directoryRole\","
                        + "\"id\":\"r1\"}],\"@odata.nextLink\":\"" + wireMock.baseUrl() + "/page2\"}")));
        wireMock.stubFor(get(urlPathEqualTo("/page2")).willReturn(okJson(
                "{\"value\":[{\"@odata.type\":\"#microsoft.graph.group\",\"id\":\"g2\",\"displayName\":null}]}")));

        assertThat(resolver.resolve("t", OID)).containsExactly(new GroupMembership("g1", "Readers"),
                new GroupMembership("g2", null));
        wireMock.verify(getRequestedFor(urlPathEqualTo(PATH)).withHeader("Authorization",
                equalTo("Bearer graph-token")));
    }

    @Test
    void cachingResolverCallsGraphOncePerUser() {
        wireMock.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson(
                "{\"value\":[{\"@odata.type\":\"#microsoft.graph.group\",\"id\":\"g1\"}]}")));
        CachingGroupMembershipResolver caching = new CachingGroupMembershipResolver(resolver,
                Duration.ofMinutes(5), 100);
        assertThat(caching.resolve("t", OID)).hasSize(1);
        assertThat(caching.resolve("t", OID)).hasSize(1);
        wireMock.verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void errorsAndBadInput() {
        wireMock.stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(403)));
        assertThatThrownBy(() -> resolver.resolve("t", OID)).isInstanceOf(GroupResolutionException.class)
                .hasMessageContaining("403");
        assertThatThrownBy(() -> resolver.resolve("t", "../me")).isInstanceOf(GroupResolutionException.class);
    }
}
