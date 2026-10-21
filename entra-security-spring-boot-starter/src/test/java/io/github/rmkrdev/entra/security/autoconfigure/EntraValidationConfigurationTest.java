package io.github.rmkrdev.entra.security.autoconfigure;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.autoconfigure.contributor.HealthContributorAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.http.converter.autoconfigure.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.reactive.ReactiveWebSecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webflux.autoconfigure.WebFluxAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import com.github.tomakehurst.wiremock.WireMockServer;

import io.github.rmkrdev.entra.security.autoconfigure.health.EntraHealthAutoConfiguration;
import io.github.rmkrdev.entra.security.core.introspect.CachingTokenIntrospector;
import io.github.rmkrdev.entra.security.core.introspect.HybridJwtDecoder;
import io.github.rmkrdev.entra.security.core.introspect.IntrospectionJwtDecoder;
import io.github.rmkrdev.entra.security.core.introspect.TokenIntrospector;

class EntraValidationConfigurationTest {

    static final WireMockServer SERVER = new WireMockServer(options().dynamicPort());

    private static final String TENANT = "entra.security.tenant-id=11111111-1111-1111-1111-111111111111";
    private static final String CLIENT = "entra.security.client-id=22222222-2222-2222-2222-222222222222";

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EntraSecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class,
                    EntraOutboundAutoConfiguration.class, EntraHealthAutoConfiguration.class,
                    HealthContributorAutoConfiguration.class, SecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class,
                    UserDetailsServiceAutoConfiguration.class, OAuth2ResourceServerAutoConfiguration.class,
                    WebMvcAutoConfiguration.class, JacksonAutoConfiguration.class,
                    HttpMessageConvertersAutoConfiguration.class))
            .withPropertyValues(TENANT, CLIENT);

    @BeforeAll
    static void start() {
        SERVER.start();
    }

    @AfterAll
    static void stop() {
        SERVER.stop();
    }

    @Test
    void jwksIsTheDefaultAndCreatesNoIntrospector() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(TokenIntrospector.class);
            assertThat(context.getBean(JwtDecoder.class)).isNotInstanceOf(IntrospectionJwtDecoder.class);
            assertThat(context).hasBean("entraJwksHealthIndicator");
        });
    }

    @Test
    void introspectionModeUsesTheRemoteDecoderAndDropsTheJwksHealthCheck() {
        runner.withPropertyValues("entra.security.validation.mode=introspection",
                "entra.security.validation.introspection.uri=https://gateway.example/introspect",
                "entra.security.validation.introspection.auth-method=none").run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(JwtDecoder.class)).isInstanceOf(IntrospectionJwtDecoder.class);
                    assertThat(context.getBean(TokenIntrospector.class)).isInstanceOf(CachingTokenIntrospector.class);
                    assertThat(context).doesNotHaveBean("entraJwksHealthIndicator");
                });
    }

    @Test
    void hybridModeUsesTheHybridDecoder() {
        runner.withPropertyValues("entra.security.validation.mode=hybrid",
                "entra.security.validation.hybrid-strategy=fallback",
                "entra.security.validation.introspection.uri=https://gateway.example/introspect",
                "entra.security.validation.introspection.auth-method=client-secret-post",
                "entra.security.validation.introspection.client-secret=s").run(context -> {
                    assertThat(context).hasNotFailed();
                    JwtDecoder decoder = context.getBean(JwtDecoder.class);
                    assertThat(decoder).isInstanceOf(HybridJwtDecoder.class);
                    assertThat(((HybridJwtDecoder) decoder).getStrategy()).isEqualTo(HybridJwtDecoder.Strategy.FALLBACK);
                });
    }

    @Test
    void rfc7662WithoutAnEndpointExplainsThatEntraHasNone() {
        runner.withPropertyValues("entra.security.validation.mode=introspection",
                "entra.security.validation.introspection.auth-method=none")
                .run(context -> assertFailure(context, "Microsoft Entra ID has no RFC 7662 endpoint"));
    }

    @Test
    void discoveredIntrospectionEndpointIsUsed() {
        SERVER.stubFor(get("/doc").willReturn(okJson("{\"issuer\":\"https://idp\",\"jwks_uri\":\"https://idp/k\","
                + "\"introspection_endpoint\":\"https://idp/introspect\"}")));
        runner.withPropertyValues("entra.security.validation.mode=introspection",
                "entra.security.validation.introspection.auth-method=none",
                "entra.security.authority.metadata-uri=" + SERVER.baseUrl() + "/doc")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void clientAuthenticationNeedsItsSettings() {
        runner.withPropertyValues("entra.security.validation.mode=introspection",
                "entra.security.validation.introspection.uri=https://gateway.example/introspect")
                .run(context -> assertFailure(context, "client-secret"));
        runner.withPropertyValues("entra.security.validation.mode=introspection",
                "entra.security.validation.introspection.uri=https://gateway.example/introspect",
                "entra.security.validation.introspection.auth-method=bearer")
                .run(context -> assertFailure(context, "auth-method=bearer requires"));
        runner.withPropertyValues("entra.security.validation.mode=introspection",
                "entra.security.validation.introspection.uri=https://gateway.example/introspect",
                "entra.security.credential.type=client-secret", "entra.security.credential.client-secret=s")
                .run(context -> assertThat(context).hasNotFailed());
        runner.withPropertyValues("entra.security.validation.mode=introspection",
                "entra.security.validation.introspection.uri=http://gateway.example/introspect",
                "entra.security.validation.introspection.auth-method=none")
                .run(context -> assertFailure(context, "entra.security.validation.introspection.uri", "uses http"));
    }

    @Test
    void userinfoModeDefaultsToTheAuthorityUserinfoEndpointAndWorksReactively() {
        SERVER.stubFor(get("/oidc/userinfo").withHeader("Authorization", equalTo("Bearer graph-token"))
                .willReturn(okJson("{\"id\":\"o-1\",\"displayName\":\"Graph User\"}")));
        new ReactiveWebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(EntraSecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class,
                        EntraReactiveSecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class, ReactiveWebSecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class,
                        WebFluxAutoConfiguration.class, JacksonAutoConfiguration.class))
                .withPropertyValues(TENANT, CLIENT, "entra.security.validation.mode=introspection",
                        "entra.security.validation.introspection.type=userinfo",
                        "entra.security.authority.graph-base-url=" + SERVER.baseUrl())
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    Jwt jwt = context.getBean(ReactiveJwtDecoder.class).decode("graph-token").block();
                    assertThat(jwt.getClaimAsString("oid")).isEqualTo("o-1");
                    assertThat(jwt.getClaimAsString("idtyp")).isEqualTo("user");
                });
    }

    @Test
    void timestampValidator() {
        Clock clock = Clock.fixed(Instant.parse("2026-10-19T00:00:00Z"), ZoneOffset.UTC);
        var validator = EntraValidation.timestamps(Duration.ofSeconds(60), clock);
        Jwt.Builder base = Jwt.withTokenValue("t").header("alg", "none").claim("sub", "s");
        assertThat(validator.validate(base.build()).hasErrors()).isFalse();
        assertThat(validator.validate(Jwt.withTokenValue("t").header("alg", "none").claim("sub", "s")
                .expiresAt(clock.instant().minusSeconds(120)).build()).hasErrors()).isTrue();
        assertThat(validator.validate(Jwt.withTokenValue("t").header("alg", "none").claim("sub", "s")
                .notBefore(clock.instant().plusSeconds(120)).build()).hasErrors()).isTrue();
        assertThat(validator.validate(Jwt.withTokenValue("t").header("alg", "none").claim("sub", "s")
                .expiresAt(clock.instant().plusSeconds(120)).notBefore(clock.instant()).build()).hasErrors()).isFalse();
    }

    private static void assertFailure(AssertableWebApplicationContext context, String... messages) {
        assertThat(context).hasFailed();
        StringBuilder all = new StringBuilder();
        for (Throwable t = context.getStartupFailure(); t != null; t = t.getCause()) {
            all.append(t.getMessage()).append('\n');
        }
        assertThat(all.toString()).contains(messages);
    }
}
