package io.github.rmkrdev.entra.security.autoconfigure;

import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Duration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.CredentialType;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.OutboundClient;

class EntraStartupSelfCheckTest {

    private static final String TENANT = "11111111-1111-1111-1111-111111111111";
    private static final String CLIENT = "22222222-2222-2222-2222-222222222222";

    private WireMockServer wireMock;

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EntraSecurityAutoConfiguration.class,
                    org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
                    org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration.class,
                    org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration.class,
                    org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration.class));

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
    void passesWithReachableJwks() {
        wireMock.stubFor(WireMock.get("/keys").willReturn(okJson(
                new io.github.rmkrdev.entra.security.core.test.TestTokens(wireMock.baseUrl()).jwksJson())));
        runner.withPropertyValues("entra.security.tenant-id=" + TENANT, "entra.security.client-id=" + CLIENT,
                "entra.security.authority.jwks-uri=" + wireMock.baseUrl() + "/keys",
                "entra.security.authority.allow-http=true", "entra.security.self-check.mode=fail").run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(EntraStartupSelfCheck.class).getProblems()).isEmpty();
                });
    }

    @Test
    void failModeStopsStartupAndWarnModeOnlyLogs() {
        String[] unreachable = { "entra.security.tenant-id=" + TENANT, "entra.security.client-id=" + CLIENT,
                "entra.security.authority.jwks-uri=http://127.0.0.1:9/keys", "entra.security.authority.allow-http=true" };
        runner.withPropertyValues(unreachable).withPropertyValues("entra.security.self-check.mode=fail")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasMessageContaining("self-check failed")
                            .hasMessageContaining("not reachable");
                });
        runner.withPropertyValues(unreachable).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(EntraStartupSelfCheck.class).getProblems()).singleElement().asString()
                    .contains("http://127.0.0.1:9/keys");
        });
        runner.withPropertyValues(unreachable).withPropertyValues("entra.security.self-check.mode=off")
                .run(context -> assertThat(context.getBean(EntraStartupSelfCheck.class).getProblems()).isEmpty());
    }

    @Test
    void checksGuidsAudienceIntrospectionAndOutboundCredentials() {
        wireMock.stubFor(any(anyUrl()).willReturn(WireMock.aResponse().withStatus(405)));
        EntraSecurityProperties properties = new EntraSecurityProperties();
        properties.setTenantId("contoso.onmicrosoft.com");
        properties.setClientId(" ");
        properties.getValidation().setMode(EntraSecurityProperties.ValidationMode.INTROSPECTION);
        properties.getValidation().getIntrospection().setUri(URI.create(wireMock.baseUrl() + "/introspect"));
        OutboundClient none = new OutboundClient();
        none.getCredential().setClientId("not-a-guid");
        OutboundClient secret = new OutboundClient();
        secret.getCredential().setType(CredentialType.CLIENT_SECRET);
        OutboundClient cert = new OutboundClient();
        cert.getCredential().setType(CredentialType.CERTIFICATE);
        OutboundClient workload = new OutboundClient();
        workload.getCredential().setType(CredentialType.WORKLOAD_IDENTITY);
        properties.getOutbound().getClients().put("a", none);
        properties.getOutbound().getClients().put("b", secret);
        properties.getOutbound().getClients().put("c", cert);
        properties.getOutbound().getClients().put("d", workload);
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("endpoints", EntraEndpoints.of(properties));
        EntraStartupSelfCheck check = new EntraStartupSelfCheck(properties,
                beans.getBeanProvider(EntraEndpoints.class), beans.getBeanProvider(
                        org.springframework.core.ResolvableType.forClassWithGenerics(
                                com.nimbusds.jose.jwk.source.JWKSource.class,
                                com.nimbusds.jose.proc.SecurityContext.class)));
        assertThat(check.check()).anyMatch(p -> p.contains("tenant-id='contoso.onmicrosoft.com' is not a GUID"))
                .anyMatch(p -> p.contains("client-id is not set"))
                .anyMatch(p -> p.contains("clients.a.credential.client-id='not-a-guid'"))
                .anyMatch(p -> p.contains("no audience"))
                .anyMatch(p -> p.startsWith("outbound client 'a': no credential"))
                .anyMatch(p -> p.startsWith("outbound client 'b': credential.type=client-secret"))
                .anyMatch(p -> p.startsWith("outbound client 'c': credential.type=certificate"))
                .noneMatch(p -> p.contains("'d'"))
                .noneMatch(p -> p.contains("introspection endpoint"));
        assertThat(EntraStartupSelfCheck.reachable(URI.create("http://127.0.0.1:9/x"), Duration.ofSeconds(1),
                Duration.ofSeconds(1))).isNotNull();
    }
}
