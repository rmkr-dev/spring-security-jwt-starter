package io.github.rmkrdev.entra.security.core.outbound;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;
import io.github.rmkrdev.entra.security.core.token.AccessToken;
import io.github.rmkrdev.entra.security.core.token.EntraInteractionRequiredException;
import io.github.rmkrdev.entra.security.core.token.EntraOnBehalfOfTokenProvider;
import io.github.rmkrdev.entra.security.core.token.EntraTokenAcquisitionException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class OnBehalfOfOutboundTest {

    private static final String SCOPE = "api://orders/Orders.Read";

    private WireMockServer wireMock;
    private final EntraOnBehalfOfTokenProvider provider = (jwt, scope) -> new AccessToken(
            "obo-for-" + jwt.getClaimAsString("oid") + "-" + scope.length(), Instant.now().plusSeconds(600));

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        wireMock.stubFor(get("/peer").willReturn(ok("pong")));
    }

    @AfterEach
    void stop() {
        wireMock.stop();
        SecurityContextHolder.clearContext();
    }

    @Test
    void restClientInterceptorExchangesTheCurrentUsersToken() {
        SecurityContextHolder.getContext().setAuthentication(entraAuthentication(user("alice")));

        String body = RestClient.builder().baseUrl(wireMock.baseUrl())
                .requestInterceptor(new EntraOnBehalfOfInterceptor(provider, SCOPE))
                .build().get().uri("/peer").retrieve().body(String.class);

        assertThat(body).isEqualTo("pong");
        wireMock.verify(getRequestedFor(urlEqualTo("/peer"))
                .withHeader("Authorization", equalTo("Bearer obo-for-alice-" + SCOPE.length())));
    }

    @Test
    void restClientInterceptorWithoutAUserTokenFailsBeforeSending() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("x", "y"));
        RestClient client = RestClient.builder().baseUrl(wireMock.baseUrl())
                .requestInterceptor(new EntraOnBehalfOfInterceptor(provider, SCOPE)).build();

        assertThatThrownBy(() -> client.get().uri("/peer").retrieve().body(String.class))
                .isInstanceOf(EntraTokenAcquisitionException.class)
                .hasMessageContaining("current user's access token");
        wireMock.verify(0, getRequestedFor(urlEqualTo("/peer")));
    }

    @Test
    void interactionRequiredReachesTheCallerUnwrapped() {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(user("alice")));
        EntraOnBehalfOfTokenProvider failing = (jwt, scope) -> {
            throw new EntraInteractionRequiredException("consent", "invalid_grant", "consent_required", scope, null,
                    List.of(65001));
        };
        RestClient client = RestClient.builder().baseUrl(wireMock.baseUrl())
                .requestInterceptor(new EntraOnBehalfOfInterceptor(failing, SCOPE)).build();

        assertThatThrownBy(() -> client.get().uri("/peer").retrieve().body(String.class))
                .isInstanceOf(EntraInteractionRequiredException.class);
    }

    @Test
    void webClientFilterReadsTheUserFromTheReactorContext() {
        WebClient client = WebClient.builder().baseUrl(wireMock.baseUrl())
                .filter(new EntraOnBehalfOfExchangeFilterFunction(provider, SCOPE)).build();

        Mono<String> call = client.get().uri("/peer").retrieve().bodyToMono(String.class)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(entraAuthentication(user("bob"))));

        StepVerifier.create(call).expectNext("pong").verifyComplete();
        wireMock.verify(getRequestedFor(urlEqualTo("/peer"))
                .withHeader("Authorization", equalTo("Bearer obo-for-bob-" + SCOPE.length())));
    }

    @Test
    void webClientFilterFallsBackToTheThreadContextWhenBlocking() {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(user("carol")));
        WebClient client = WebClient.builder().baseUrl(wireMock.baseUrl())
                .filter(new EntraOnBehalfOfExchangeFilterFunction(provider, SCOPE)).build();

        assertThat(client.get().uri("/peer").retrieve().bodyToMono(String.class).block()).isEqualTo("pong");
        wireMock.verify(getRequestedFor(urlEqualTo("/peer"))
                .withHeader("Authorization", equalTo("Bearer obo-for-carol-" + SCOPE.length())));
    }

    @Test
    void webClientFilterWithoutAUserErrors() {
        WebClient client = WebClient.builder().baseUrl(wireMock.baseUrl())
                .filter(new EntraOnBehalfOfExchangeFilterFunction(provider, SCOPE)).build();

        StepVerifier.create(client.get().uri("/peer").retrieve().bodyToMono(String.class))
                .expectError(EntraTokenAcquisitionException.class)
                .verify();
        wireMock.verify(0, getRequestedFor(urlEqualTo("/peer")));
    }

    @Test
    void userTokensAreFoundBehindEntraAndPlainJwtAuthentications() {
        Jwt jwt = user("dave");
        assertThat(EntraUserTokens.from(entraAuthentication(jwt))).contains(jwt);
        assertThat(EntraUserTokens.from(new JwtAuthenticationToken(jwt))).contains(jwt);
        assertThat(EntraUserTokens.from(new TestingAuthenticationToken("p", "c"))).isEmpty();
        assertThat(EntraUserTokens.from(null)).isEmpty();
    }

    private static Jwt user(String oid) {
        return Jwt.withTokenValue("incoming-" + oid).header("alg", "RS256")
                .claim("oid", oid).claim("tid", "t").claim("scp", "access_as_user").build();
    }

    private static EntraAuthenticationToken entraAuthentication(Jwt jwt) {
        EntraPrincipal principal = new EntraPrincipal(PrincipalType.USER, "t", jwt.getClaimAsString("oid"), null,
                "spa", null, null, null, null, null, null, "2.0");
        return new EntraAuthenticationToken(jwt, principal, List.of());
    }
}
