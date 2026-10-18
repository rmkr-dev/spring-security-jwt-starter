package io.github.rmkrdev.entra.security.core.graph;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.token.AccessToken;
import reactor.test.StepVerifier;

class ReactiveGraphGroupMembershipResolverTest {

    private static final String OID = "33333333-3333-3333-3333-333333333333";
    private static final String PATH = "/v1.0/users/" + OID + "/transitiveMemberOf";
    private static final String GROUP = "{\"value\":[{\"@odata.type\":\"#microsoft.graph.group\",\"id\":\"g1\"}]}";

    private WireMockServer wireMock;
    private ReactiveGraphGroupMembershipResolver resolver;

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        resolver = resolver(5, Duration.ofSeconds(5), EntraSecurityObservations.NO_OP);
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

        StepVerifier.create(resolver.resolve("t", OID))
                .assertNext(groups -> assertThat(groups).containsExactly(new GroupMembership("g1", "Readers"),
                        new GroupMembership("g2", null)))
                .verifyComplete();
        wireMock.verify(getRequestedFor(urlPathEqualTo(PATH)).withHeader("Authorization",
                equalTo("Bearer graph-token")));
    }

    @Test
    void stopsAfterMaxPages() {
        wireMock.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson(
                "{\"value\":[],\"@odata.nextLink\":\"" + wireMock.baseUrl() + PATH + "\"}")));
        StepVerifier.create(resolver(2, null, null).resolve("t", OID))
                .expectErrorSatisfies(error -> assertThat(error).isInstanceOf(GroupResolutionException.class)
                        .hasMessage("Graph group lookup exceeded 2 pages"))
                .verify();
        wireMock.verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void errorsAndBadInput() {
        wireMock.stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(403)));
        StepVerifier.create(resolver.resolve("t", OID))
                .expectErrorSatisfies(error -> assertThat(error).isInstanceOf(GroupResolutionException.class)
                        .hasMessage("Graph group lookup failed with HTTP 403"))
                .verify();
        StepVerifier.create(resolver.resolve("t", "../me"))
                .expectError(GroupResolutionException.class)
                .verify();
        wireMock.verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void slowGraphTimesOut() {
        wireMock.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson(GROUP).withFixedDelay(2000)));
        StepVerifier.create(resolver(5, Duration.ofMillis(200), null).resolve("t", OID))
                .expectErrorSatisfies(error -> assertThat(error).isInstanceOf(GroupResolutionException.class)
                        .hasMessageContaining("timed out"))
                .verify(Duration.ofSeconds(5));
    }

    @Test
    void cachingCallsGraphOncePerUserAndSkipsFailures() {
        List<Boolean> results = new ArrayList<>();
        CachingReactiveGroupMembershipResolver caching = new CachingReactiveGroupMembershipResolver(
                resolver(5, null, new EntraSecurityObservations() {
                    @Override
                    public void graphLookup(boolean success, Duration duration) {
                        assertThat(duration).isGreaterThanOrEqualTo(Duration.ZERO);
                        results.add(success);
                    }
                }), Duration.ofMinutes(5), 100);

        wireMock.stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(503)));
        StepVerifier.create(caching.resolve("t", OID)).expectError(GroupResolutionException.class).verify();

        wireMock.resetAll();
        wireMock.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson(GROUP)));
        StepVerifier.create(caching.resolve("t", OID)).assertNext(groups -> assertThat(groups).hasSize(1))
                .verifyComplete();
        StepVerifier.create(caching.resolve("t", OID)).assertNext(groups -> assertThat(groups).hasSize(1))
                .verifyComplete();

        wireMock.verify(1, getRequestedFor(urlPathEqualTo(PATH)));
        assertThat(results).containsExactly(false, true);
    }

    private ReactiveGraphGroupMembershipResolver resolver(int maxPages, Duration timeout,
            EntraSecurityObservations observations) {
        return new ReactiveGraphGroupMembershipResolver(WebClient.create(),
                scope -> new AccessToken("graph-token", Instant.now().plusSeconds(3600)),
                URI.create(wireMock.baseUrl() + "/"), "https://graph.microsoft.com/.default", maxPages, timeout,
                observations);
    }
}
