package io.github.rmkrdev.entra.security.core.cae;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.core.outbound.EntraBearerExchangeFilterFunction;
import io.github.rmkrdev.entra.security.core.outbound.EntraBearerTokenInterceptor;
import io.github.rmkrdev.entra.security.core.outbound.EntraOnBehalfOfExchangeFilterFunction;
import io.github.rmkrdev.entra.security.core.outbound.EntraOnBehalfOfInterceptor;
import io.github.rmkrdev.entra.security.core.token.AccessToken;
import io.github.rmkrdev.entra.security.core.token.ClientCredentialsTokenProvider;
import io.github.rmkrdev.entra.security.core.token.ClientSecretCredential;
import io.github.rmkrdev.entra.security.core.token.EntraOnBehalfOfTokenProvider;
import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;
import io.github.rmkrdev.entra.security.core.token.OnBehalfOfTokenProvider;

class ContinuousAccessEvaluationTest {

    private static final String CHALLENGE_CLAIMS = "{\"access_token\":{\"nbf\":{\"essential\":true,\"value\":\"1\"}}}";
    private static final String CHALLENGE = "Bearer realm=\"\", error=\"insufficient_claims\", "
            + "error_description=\"token revoked\", claims=\""
            + Base64.getEncoder().encodeToString(CHALLENGE_CLAIMS.getBytes(StandardCharsets.UTF_8)) + "\"";

    private WireMockServer wireMock;

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    @Test
    void requestClaimsDeclareCp1AndMergeChallenges() {
        assertThat(ContinuousAccessEvaluation.requestClaims(false, null)).isNull();
        assertThat(ContinuousAccessEvaluation.requestClaims(true, " ")).isEqualTo(ContinuousAccessEvaluation.CP1_CLAIMS);
        assertThat(ContinuousAccessEvaluation.requestClaims(false, CHALLENGE_CLAIMS)).isEqualTo(CHALLENGE_CLAIMS);
        assertThat(ContinuousAccessEvaluation.requestClaims(true, CHALLENGE_CLAIMS)).contains("\"nbf\"")
                .contains("\"xms_cc\":{\"values\":[\"cp1\"]}");
        assertThat(ContinuousAccessEvaluation.requestClaims(true, ContinuousAccessEvaluation.CP1_CLAIMS))
                .isEqualTo(ContinuousAccessEvaluation.CP1_CLAIMS);
        assertThat(ContinuousAccessEvaluation.requestClaims(true, "not json")).isEqualTo("not json");
        assertThat(ContinuousAccessEvaluation.requestClaims(true, "[1]")).contains("cp1");
    }

    @Test
    void challengesAreParsedAndBuilt() {
        assertThat(ContinuousAccessEvaluation.claimsChallenge(CHALLENGE)).contains(CHALLENGE_CLAIMS);
        assertThat(ContinuousAccessEvaluation.claimsChallenge(null)).isEmpty();
        assertThat(ContinuousAccessEvaluation.claimsChallenge("Bearer error=\"invalid_token\"")).isEmpty();
        assertThat(ContinuousAccessEvaluation.claimsChallenge("Bearer error=insufficient_claims")).isEmpty();
        assertThat(ContinuousAccessEvaluation.claimsChallenge("Bearer error=insufficient_claims, claims=\""
                + Base64.getUrlEncoder().encodeToString("{\"a\":\"?>\"}".getBytes(StandardCharsets.UTF_8)) + "\""))
                .contains("{\"a\":\"?>\"}");
        assertThat(ContinuousAccessEvaluation.claimsChallenge("Bearer error=insufficient_claims, claims=\"{x}\""))
                .contains("{x}");
        assertThat(ContinuousAccessEvaluation.claimsChallenge("Bearer error=insufficient_claims, claims=\"%%\""))
                .isEmpty();
        String header = ContinuousAccessEvaluation.challengeHeader(CHALLENGE_CLAIMS, "say \"hi\"");
        assertThat(ContinuousAccessEvaluation.claimsChallenge(header)).contains(CHALLENGE_CLAIMS);
        assertThat(header).contains("say 'hi'");
        assertThat(ContinuousAccessEvaluation.challengeHeader("{}", null)).contains("Additional claims");
    }

    @Test
    void cp1IsReadFromXmsCc() {
        assertThat(ContinuousAccessEvaluation.supportsClaimsChallenge(jwt(List.of("CP1")))).isTrue();
        assertThat(ContinuousAccessEvaluation.supportsClaimsChallenge(jwt("cp1"))).isTrue();
        assertThat(ContinuousAccessEvaluation.supportsClaimsChallenge(jwt(List.of("x")))).isFalse();
        assertThat(ContinuousAccessEvaluation.supportsClaimsChallenge(jwt(null))).isFalse();
        assertThat(ContinuousAccessEvaluation.supportsClaimsChallenge(null)).isFalse();
    }

    @Test
    void inboundChallengeOnlyForCp1Callers() {
        ClaimsChallengeException ex = new ClaimsChallengeException(CHALLENGE_CLAIMS, "Session revoked");
        var capable = ClaimsChallengeResponses.response(ex, new JwtAuthenticationToken(jwt(List.of("cp1"))), "/x");
        assertThat(capable.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(ContinuousAccessEvaluation.claimsChallenge(capable.getHeaders().getFirst("WWW-Authenticate")))
                .contains(CHALLENGE_CLAIMS);
        var plain = ClaimsChallengeResponses.response(ex, new JwtAuthenticationToken(jwt(null)), "/x");
        assertThat(plain.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(plain.getHeaders().getFirst("WWW-Authenticate")).isNull();
        assertThat(ClaimsChallengeResponses.response(ex, new TestingAuthenticationToken("u", "p"), "/x")
                .getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(ex.getClaims()).isEqualTo(CHALLENGE_CLAIMS);
    }

    @Test
    void restClientRetriesOnceWithChallengeClaims() {
        stubChallengeThenOk();
        List<String> claimsSeen = new ArrayList<>();
        String body = RestClient.builder().baseUrl(wireMock.baseUrl())
                .requestInterceptor(new EntraBearerTokenInterceptor(provider(claimsSeen), "s", true))
                .build().get().uri("/peer").retrieve().body(String.class);
        assertThat(body).isEqualTo("pong");
        assertThat(claimsSeen).containsExactly(CHALLENGE_CLAIMS);
        wireMock.verify(getRequestedFor(urlEqualTo("/peer")).withHeader("Authorization", equalTo("Bearer second")));
    }

    @Test
    void webClientRetriesOnceWithChallengeClaims() {
        stubChallengeThenOk();
        List<String> claimsSeen = new ArrayList<>();
        String body = WebClient.builder().baseUrl(wireMock.baseUrl())
                .filter(new EntraBearerExchangeFilterFunction(provider(claimsSeen), "s", true))
                .build().get().uri("/peer").retrieve().bodyToMono(String.class).block();
        assertThat(body).isEqualTo("pong");
        assertThat(claimsSeen).containsExactly(CHALLENGE_CLAIMS);
    }

    @Test
    void onBehalfOfInterceptorsRetryToo() {
        stubChallengeThenOk();
        List<String> claimsSeen = new ArrayList<>();
        EntraOnBehalfOfTokenProvider obo = new EntraOnBehalfOfTokenProvider() {
            @Override
            public AccessToken getToken(Jwt userToken, String scope) {
                return new AccessToken("first", Instant.now().plusSeconds(600));
            }

            @Override
            public AccessToken getToken(Jwt userToken, String scope, String claims) {
                claimsSeen.add(claims);
                return new AccessToken("second", Instant.now().plusSeconds(600));
            }
        };
        Jwt user = jwt(null);
        assertThat(RestClient.builder().baseUrl(wireMock.baseUrl())
                .requestInterceptor(new EntraOnBehalfOfInterceptor(obo, "s", () -> user, true))
                .build().get().uri("/peer").retrieve().body(String.class)).isEqualTo("pong");
        wireMock.resetScenarios();
        org.springframework.security.core.context.SecurityContextHolder.getContext()
                .setAuthentication(new JwtAuthenticationToken(user));
        try {
            assertThat(WebClient.builder().baseUrl(wireMock.baseUrl())
                    .filter(new EntraOnBehalfOfExchangeFilterFunction(obo, "s", true))
                    .build().get().uri("/peer").retrieve().bodyToMono(String.class).block()).isEqualTo("pong");
        }
        finally {
            org.springframework.security.core.context.SecurityContextHolder.clearContext();
        }
        assertThat(claimsSeen).hasSize(2);
    }

    @Test
    void otherResponsesAreNotRetriedAndCaeOffPassesChallengesThrough() {
        wireMock.stubFor(get("/peer").willReturn(aResponse().withStatus(401)
                .withHeader("WWW-Authenticate", CHALLENGE)));
        List<String> claimsSeen = new ArrayList<>();
        RestClient off = RestClient.builder().baseUrl(wireMock.baseUrl())
                .requestInterceptor(new EntraBearerTokenInterceptor(provider(claimsSeen), "s"))
                .defaultStatusHandler(status -> true, (request, response) -> {
                })
                .build();
        assertThat(off.get().uri("/peer").retrieve().toBodilessEntity().getStatusCode().value()).isEqualTo(401);
        wireMock.stubFor(get("/other").willReturn(aResponse().withStatus(401)
                .withHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"")));
        RestClient on = RestClient.builder().baseUrl(wireMock.baseUrl())
                .requestInterceptor(new EntraBearerTokenInterceptor(provider(claimsSeen), "s", true))
                .defaultStatusHandler(status -> true, (request, response) -> {
                })
                .build();
        assertThat(on.get().uri("/other").retrieve().toBodilessEntity().getStatusCode().value()).isEqualTo(401);
        assertThat(claimsSeen).isEmpty();
    }

    @Test
    void tokenProvidersSendCp1AndChallengeClaims() {
        String tenant = "11111111-1111-1111-1111-111111111111";
        String path = "/" + tenant + "/oauth2/v2.0/token";
        wireMock.stubFor(post(path).willReturn(aResponse().withHeader("Content-Type", "application/json")
                .withBody("{\"token_type\":\"Bearer\",\"expires_in\":3600,\"access_token\":\"t\"}")));
        URI endpoint = ClientCredentialsTokenProvider.tokenEndpoint(URI.create(wireMock.baseUrl()), tenant);
        ClientCredentialsTokenProvider cc = new ClientCredentialsTokenProvider(endpoint, "app",
                new ClientSecretCredential("s"), RestClient.create(), Duration.ofMinutes(5), Clock.systemUTC())
                .withClientCapabilities();
        cc.getToken("a");
        wireMock.verify(postRequestedFor(urlEqualTo(path)).withRequestBody(containing("xms_cc")));
        assertThat(cc.getToken("a", " ").value()).isEqualTo("t");
        cc.getToken("a", CHALLENGE_CLAIMS);
        wireMock.verify(postRequestedFor(urlEqualTo(path)).withRequestBody(containing("nbf")));

        OnBehalfOfTokenProvider obo = new OnBehalfOfTokenProvider(endpoint, "app", new ClientSecretCredential("s"),
                RestClient.create(), Duration.ofMinutes(5), 100, Clock.systemUTC(),
                io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations.NO_OP)
                .withClientCapabilities();
        Jwt user = Jwt.withTokenValue("user-token").header("alg", "RS256").claim("scp", "x").claim("oid", "o")
                .claim("tid", tenant).issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(600)).build();
        assertThat(obo.getToken(user, "api://x/.default", CHALLENGE_CLAIMS).value()).isEqualTo("t");
        assertThat(obo.getToken(user, "api://x/.default", null).value()).isEqualTo("t");
        wireMock.verify(postRequestedFor(urlEqualTo(path)).withRequestBody(containing("on_behalf_of"))
                .withRequestBody(containing("cp1")));
        EntraTokenProvider plain = scope -> new AccessToken("p", Instant.now());
        assertThat(plain.getToken("s", "c").value()).isEqualTo("p");
    }

    private void stubChallengeThenOk() {
        wireMock.stubFor(get("/peer").inScenario("cae").whenScenarioStateIs(STARTED)
                .willReturn(aResponse().withStatus(401).withHeader("WWW-Authenticate", CHALLENGE))
                .willSetStateTo("retried"));
        wireMock.stubFor(get("/peer").inScenario("cae").whenScenarioStateIs("retried").willReturn(ok("pong")));
    }

    private static EntraTokenProvider provider(List<String> claimsSeen) {
        return new EntraTokenProvider() {
            @Override
            public AccessToken getToken(String scope) {
                return new AccessToken("first", Instant.now().plusSeconds(600));
            }

            @Override
            public AccessToken getToken(String scope, String claims) {
                claimsSeen.add(claims);
                return new AccessToken("second", Instant.now().plusSeconds(600));
            }
        };
    }

    private static Jwt jwt(Object xmsCc) {
        Jwt.Builder builder = Jwt.withTokenValue("t").header("alg", "RS256").claim("sub", "s").claim("scp", "x");
        if (xmsCc != null) {
            builder.claim("xms_cc", xmsCc);
        }
        return builder.build();
    }
}
