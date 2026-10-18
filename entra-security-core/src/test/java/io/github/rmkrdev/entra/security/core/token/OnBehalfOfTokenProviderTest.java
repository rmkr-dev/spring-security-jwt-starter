package io.github.rmkrdev.entra.security.core.token;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.notContaining;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestClient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.stubbing.Scenario;

import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;

class OnBehalfOfTokenProviderTest {

    private static final String TENANT = "11111111-1111-1111-1111-111111111111";
    private static final String OTHER_TENANT = "99999999-9999-9999-9999-999999999999";
    private static final String CLIENT_ID = "22222222-2222-2222-2222-222222222222";
    private static final String TOKEN_PATH = "/" + TENANT + "/oauth2/v2.0/token";
    private static final String ALICE = "a1a1a1a1-0000-4000-8000-000000000001";
    private static final String BOB = "b2b2b2b2-0000-4000-8000-000000000002";
    private static final String SCOPE = "api://orders/Orders.Read";

    private final MutableClock clock = new MutableClock();
    private WireMockServer wireMock;
    private URI tokenEndpoint;

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        tokenEndpoint = ClientCredentialsTokenProvider.tokenEndpoint(URI.create(wireMock.baseUrl()), TENANT);
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    @Test
    void exchangesTheUserTokenWithTheJwtBearerGrant() {
        stubToken("obo-1", 3600);
        OnBehalfOfTokenProvider provider = provider(new ClientSecretCredential("s3cret"));

        AccessToken token = provider.getToken(user(ALICE, TENANT, "incoming-alice"), SCOPE);

        assertThat(token.value()).isEqualTo("obo-1");
        assertThat(token.expiresAt()).isEqualTo(clock.instant().plusSeconds(3600));
        wireMock.verify(1, postRequestedFor(urlEqualTo(TOKEN_PATH))
                .withRequestBody(containing("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"))
                .withRequestBody(containing("client_id=" + CLIENT_ID))
                .withRequestBody(containing("assertion=incoming-alice"))
                .withRequestBody(containing("requested_token_use=on_behalf_of"))
                .withRequestBody(containing("scope=api%3A%2F%2Forders%2FOrders.Read"))
                .withRequestBody(containing("client_secret=s3cret")));
    }

    @Test
    void tokensAreCachedPerUserTenantAndScope() {
        stubToken("obo", 3600);
        OnBehalfOfTokenProvider provider = provider(new ClientSecretCredential("s"));

        provider.getToken(user(ALICE, TENANT, "alice-1"), SCOPE);
        provider.getToken(user(ALICE, TENANT, "alice-2-new-incoming-token"), SCOPE);
        wireMock.verify(1, postRequestedFor(urlEqualTo(TOKEN_PATH)));

        provider.getToken(user(ALICE, TENANT, "alice-1"), "api://orders/Orders.Write");
        provider.getToken(user(BOB, TENANT, "bob-1"), SCOPE);
        provider.getToken(user(ALICE, OTHER_TENANT, "alice-guest"), SCOPE);
        wireMock.verify(4, postRequestedFor(urlEqualTo(TOKEN_PATH)));
        assertThat(provider.size()).isEqualTo(4);

        provider.invalidate(user(BOB, TENANT, "bob-1"), SCOPE);
        assertThat(provider.size()).isEqualTo(3);
    }

    @Test
    void cacheKeyIsAHashThatIgnoresScopeOrderAndDoesNotRevealTheUser() {
        String key = OnBehalfOfTokenProvider.cacheKey(user(ALICE, TENANT, "t"), "api://a/X api://a/Y");

        assertThat(key).isEqualTo(OnBehalfOfTokenProvider.cacheKey(user(ALICE, TENANT, "other"),
                "  api://a/Y   api://a/X api://a/Y"));
        assertThat(key).doesNotContain(ALICE).doesNotContain(TENANT).doesNotContain("api://");
        assertThat(key).matches("[A-Za-z0-9_-]{43}");
        assertThat(key).isNotEqualTo(OnBehalfOfTokenProvider.cacheKey(user(BOB, TENANT, "t"), "api://a/X api://a/Y"));
        assertThat(key).isNotEqualTo(OnBehalfOfTokenProvider.cacheKey(user(ALICE, OTHER_TENANT, "t"),
                "api://a/X api://a/Y"));
    }

    @Test
    void tokensAreRenewedBeforeTheyExpire() {
        stubToken("obo", 3600);
        OnBehalfOfTokenProvider provider = provider(new ClientSecretCredential("s"));
        Jwt alice = user(ALICE, TENANT, "alice");

        provider.getToken(alice, SCOPE);
        clock.advance(Duration.ofMinutes(54));
        provider.getToken(alice, SCOPE);
        wireMock.verify(1, postRequestedFor(urlEqualTo(TOKEN_PATH)));

        clock.advance(Duration.ofMinutes(2));   // 56 minutes: inside the 5 minute refresh window
        provider.getToken(alice, SCOPE);
        wireMock.verify(2, postRequestedFor(urlEqualTo(TOKEN_PATH)));
    }

    @Test
    void aFailedRenewalKeepsUsingTheCachedTokenUntilItExpires() {
        wireMock.stubFor(post(TOKEN_PATH).inScenario("renewal").whenScenarioStateIs(Scenario.STARTED)
                .willReturn(okJson("{\"expires_in\":3600,\"access_token\":\"first\"}"))
                .willSetStateTo("down"));
        wireMock.stubFor(post(TOKEN_PATH).inScenario("renewal").whenScenarioStateIs("down")
                .willReturn(aResponse().withStatus(503)));
        OnBehalfOfTokenProvider provider = provider(new ClientSecretCredential("s"));
        Jwt alice = user(ALICE, TENANT, "alice");

        provider.getToken(alice, SCOPE);
        clock.advance(Duration.ofMinutes(57));
        assertThat(provider.getToken(alice, SCOPE).value()).isEqualTo("first");

        clock.advance(Duration.ofMinutes(4));
        assertThatThrownBy(() -> provider.getToken(alice, SCOPE))
                .isExactlyInstanceOf(EntraTokenAcquisitionException.class)
                .hasMessageContaining("HTTP 503");
    }

    @Test
    void missingConsentIsAnInteractionRequiredException() {
        wireMock.stubFor(post(TOKEN_PATH).willReturn(aResponse().withStatus(400)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"error\":\"invalid_grant\",\"error_description\":\"AADSTS65001: The user or "
                        + "administrator has not consented to use the application.\\r\\nTrace ID: x\","
                        + "\"error_codes\":[65001],\"suberror\":\"consent_required\"}")));
        OnBehalfOfTokenProvider provider = provider(new ClientSecretCredential("s3cret"));

        assertThatThrownBy(() -> provider.getToken(user(ALICE, TENANT, "the-user-assertion"), SCOPE))
                .isInstanceOfSatisfying(EntraInteractionRequiredException.class, ex -> {
                    assertThat(ex.isConsentRequired()).isTrue();
                    assertThat(ex.getProblemErrorCode()).isEqualTo("consent_required");
                    assertThat(ex.getError()).isEqualTo("invalid_grant");
                    assertThat(ex.getSuberror()).isEqualTo("consent_required");
                    assertThat(ex.getErrorCodes()).containsExactly(65001);
                    assertThat(ex.getScope()).isEqualTo(SCOPE);
                    assertThat(ex.getClaims()).isNull();
                    assertThat(ex.getMessage()).contains("AADSTS65001").contains("consent to '" + SCOPE + "'")
                            .doesNotContain("s3cret").doesNotContain("the-user-assertion");
                });
    }

    @Test
    void conditionalAccessChallengeCarriesTheClaims() {
        String claims = "{\"access_token\":{\"capolids\":{\"essential\":true,\"values\":[\"p1\"]}}}";
        wireMock.stubFor(post(TOKEN_PATH).willReturn(aResponse().withStatus(400)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"error\":\"interaction_required\",\"error_description\":\"AADSTS50076: you must use "
                        + "multi-factor authentication\",\"error_codes\":[50076],\"suberror\":\"basic_action\","
                        + "\"claims\":" + com.fasterxml.jackson.databind.node.TextNode.valueOf(claims) + "}")));
        OnBehalfOfTokenProvider provider = provider(new ClientSecretCredential("s"));

        assertThatThrownBy(() -> provider.getToken(user(ALICE, TENANT, "a"), SCOPE))
                .isInstanceOfSatisfying(EntraInteractionRequiredException.class, ex -> {
                    assertThat(ex.isConsentRequired()).isFalse();
                    assertThat(ex.getProblemErrorCode()).isEqualTo("interaction_required");
                    assertThat(ex.getClaims()).isEqualTo(claims);
                    assertThat(ex.getMessage()).contains("sign in again interactively");
                });
    }

    @Test
    void consentCodeInTheDescriptionAloneIsRecognised() {
        wireMock.stubFor(post(TOKEN_PATH).willReturn(aResponse().withStatus(400)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"error\":\"invalid_grant\",\"error_description\":\"AADSTS65001: no consent\"}")));
        OnBehalfOfTokenProvider provider = provider(new ClientSecretCredential("s"));

        assertThatThrownBy(() -> provider.getToken(user(ALICE, TENANT, "a"), SCOPE))
                .isInstanceOfSatisfying(EntraInteractionRequiredException.class,
                        ex -> assertThat(ex.isConsentRequired()).isTrue());
    }

    @Test
    void otherErrorsAreOrdinaryAcquisitionFailures() {
        wireMock.stubFor(post(TOKEN_PATH).willReturn(aResponse().withStatus(401)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"error\":\"invalid_client\",\"error_description\":\"AADSTS7000215: Invalid client "
                        + "secret provided.\",\"error_codes\":[7000215]}")));
        OnBehalfOfTokenProvider provider = provider(new ClientSecretCredential("s3cret"));

        assertThatThrownBy(() -> provider.getToken(user(ALICE, TENANT, "a"), SCOPE))
                .isExactlyInstanceOf(EntraTokenAcquisitionException.class)
                .hasMessageStartingWith("On-behalf-of token request to " + tokenEndpoint)
                .hasMessageContaining("invalid_client")
                .hasMessageNotContaining("s3cret");
    }

    @Test
    void anInteractionErrorIsNotServedFromCacheAndClearsTheEntry() {
        wireMock.stubFor(post(TOKEN_PATH).inScenario("ca").whenScenarioStateIs(Scenario.STARTED)
                .willReturn(okJson("{\"expires_in\":3600,\"access_token\":\"first\"}"))
                .willSetStateTo("mfa"));
        wireMock.stubFor(post(TOKEN_PATH).inScenario("ca").whenScenarioStateIs("mfa")
                .willReturn(aResponse().withStatus(400).withHeader("Content-Type", "application/json")
                        .withBody("{\"error\":\"interaction_required\",\"error_codes\":[50076]}")));
        OnBehalfOfTokenProvider provider = provider(new ClientSecretCredential("s"));
        Jwt alice = user(ALICE, TENANT, "alice");

        provider.getToken(alice, SCOPE);
        clock.advance(Duration.ofMinutes(57));
        assertThatThrownBy(() -> provider.getToken(alice, SCOPE)).isInstanceOf(EntraInteractionRequiredException.class);
        assertThat(provider.size()).isZero();
    }

    @Test
    void appOnlyTokensAreRefusedWithoutCallingEntra() {
        OnBehalfOfTokenProvider provider = provider(new ClientSecretCredential("s"));
        Jwt service = Jwt.withTokenValue("app-token").header("alg", "RS256")
                .claim("oid", BOB).claim("tid", TENANT).claim("idtyp", "app").claim("roles", List.of("Orders.Sync"))
                .build();

        assertThatThrownBy(() -> provider.getToken(service, SCOPE))
                .isInstanceOf(EntraTokenAcquisitionException.class)
                .hasMessageContaining("app-only")
                .satisfies(ex -> assertThat(((EntraTokenAcquisitionException) ex).getError())
                        .isEqualTo("invalid_request"));
        wireMock.verify(0, postRequestedFor(urlEqualTo(TOKEN_PATH)));
    }

    @Test
    void workloadIdentitySendsTheFederatedTokenAsClientAssertion(@TempDir Path dir) throws Exception {
        stubToken("obo-wi", 3600);
        Path file = dir.resolve("azure-identity-token");
        Files.writeString(file, "projected-sa-jwt");
        OnBehalfOfTokenProvider provider = provider(new WorkloadIdentityCredential(file));

        assertThat(provider.getToken(user(ALICE, TENANT, "alice"), SCOPE).value()).isEqualTo("obo-wi");
        wireMock.verify(postRequestedFor(urlEqualTo(TOKEN_PATH))
                .withRequestBody(containing("assertion=alice"))
                .withRequestBody(containing("client_assertion=projected-sa-jwt"))
                .withRequestBody(containing("client_assertion_type="
                        + "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"))
                .withRequestBody(notContaining("client_secret")));
    }

    @Test
    void cacheIsBounded() {
        stubToken("obo", 3600);
        OnBehalfOfTokenProvider provider = new OnBehalfOfTokenProvider(tokenEndpoint, CLIENT_ID,
                new ClientSecretCredential("s"), RestClient.create(), Duration.ofMinutes(5), 2, clock, null);

        provider.getToken(user(ALICE, TENANT, "a"), "api://x/A");
        provider.getToken(user(ALICE, TENANT, "a"), "api://x/B");
        provider.getToken(user(ALICE, TENANT, "a"), "api://x/C");

        assertThat(provider.size()).isLessThanOrEqualTo(2);
    }

    @Test
    void tokenEndpointCallsAreObservedWithTheOnBehalfOfGrant() {
        stubToken("obo", 3600);
        List<String> calls = new ArrayList<>();
        EntraSecurityObservations observations = new EntraSecurityObservations() {
            @Override
            public void tokenAcquisition(String grant, String credentialType, boolean success, Duration duration) {
                calls.add(grant + ":" + credentialType + ":" + success);
            }
        };
        OnBehalfOfTokenProvider provider = new OnBehalfOfTokenProvider(tokenEndpoint, CLIENT_ID,
                new ClientSecretCredential("s"), RestClient.create(), Duration.ofMinutes(5), 100, clock, observations);

        provider.getToken(user(ALICE, TENANT, "a"), SCOPE);
        provider.getToken(user(ALICE, TENANT, "a"), SCOPE);

        assertThat(calls).containsExactly("on_behalf_of:client_secret:true");
    }

    @Test
    void defaultObservationsIgnoreOnBehalfOfForLegacyImplementations() {
        List<String> calls = new ArrayList<>();
        EntraSecurityObservations legacy = new EntraSecurityObservations() {
            @Override
            public void tokenAcquisition(String credentialType, boolean success, Duration duration) {
                calls.add(credentialType);
            }
        };
        legacy.tokenAcquisition(EntraSecurityObservations.GRANT_ON_BEHALF_OF, "certificate", true, Duration.ZERO);
        legacy.tokenAcquisition(EntraSecurityObservations.GRANT_CLIENT_CREDENTIALS, "certificate", true, Duration.ZERO);
        assertThat(calls).containsExactly("certificate");
    }

    private OnBehalfOfTokenProvider provider(EntraCredential credential) {
        return new OnBehalfOfTokenProvider(tokenEndpoint, CLIENT_ID, credential, RestClient.create(),
                Duration.ofMinutes(5), 1000, clock, EntraSecurityObservations.NO_OP);
    }

    private void stubToken(String value, int expiresIn) {
        wireMock.stubFor(post(TOKEN_PATH).withRequestBody(containing("requested_token_use=on_behalf_of"))
                .withHeader("Content-Type", containing("application/x-www-form-urlencoded"))
                .withHeader("Accept", equalTo("application/json"))
                .willReturn(okJson("{\"token_type\":\"Bearer\",\"expires_in\":" + expiresIn
                        + ",\"access_token\":\"" + value + "\"}")));
    }

    static Jwt user(String oid, String tid, String tokenValue) {
        return Jwt.withTokenValue(tokenValue).header("alg", "RS256")
                .claim("oid", oid).claim("tid", tid).claim("sub", "sub-" + oid).claim("scp", "access_as_user")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .build();
    }

    static final class MutableClock extends Clock {

        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
