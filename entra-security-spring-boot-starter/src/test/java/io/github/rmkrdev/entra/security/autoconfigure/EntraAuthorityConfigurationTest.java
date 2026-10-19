package io.github.rmkrdev.entra.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

/**
 * Validation of {@code entra.security.authority.*}.
 */
class EntraAuthorityConfigurationTest {

    private static final String TENANT = "entra.security.tenant-id=11111111-1111-1111-1111-111111111111";
    private static final String CLIENT = "entra.security.client-id=22222222-2222-2222-2222-222222222222";

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EntraSecurityAutoConfiguration.class,
                    EntraOutboundAutoConfiguration.class, SecurityAutoConfiguration.class,
                    UserDetailsServiceAutoConfiguration.class, OAuth2ResourceServerAutoConfiguration.class,
                    WebMvcAutoConfiguration.class, JacksonAutoConfiguration.class,
                    HttpMessageConvertersAutoConfiguration.class))
            .withPropertyValues(TENANT, CLIENT);

    @Test
    void nothingConfiguredKeepsTheDefaults() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            EntraEndpoints endpoints = context.getBean(EntraEndpoints.class);
            assertThat(endpoints.jwksUri()).hasToString(
                    "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys");
            assertThat(endpoints.isDiscovered()).isFalse();
        });
    }

    @Test
    void validOverridesAreAccepted() {
        runner.withPropertyValues("entra.security.authority.host=https://login.microsoftonline.us",
                "entra.security.authority.tenant-path=contoso.onmicrosoft.com/B2C_1_signin",
                "entra.security.authority.issuers=https://contoso.b2clogin.com/tid/v2.0/",
                "entra.security.authority.jwks-uri=https://contoso.b2clogin.com/keys",
                "entra.security.authority.token-endpoint=http://localhost:8080/token",
                "entra.security.authority.graph-base-url=https://graph.microsoft.us").run(context -> {
                    assertThat(context).hasNotFailed();
                    EntraEndpoints endpoints = context.getBean(EntraEndpoints.class);
                    assertThat(endpoints.issuers()).containsExactly("https://contoso.b2clogin.com/tid/v2.0/");
                    assertThat(endpoints.tokenEndpoint()).hasToString("http://localhost:8080/token");
                    assertThat(endpoints.graphBaseUrl()).hasToString("https://graph.microsoft.us");
                });
    }

    @Test
    void plainHttpNeedsAllowHttpOutsideLoopback() {
        runner.withPropertyValues("entra.security.authority.jwks-uri=http://idp.auth.svc.cluster.local/keys")
                .run(context -> assertFailure(context, "entra.security.authority.jwks-uri",
                        "uses http", "allow-http=true"));
        runner.withPropertyValues("entra.security.authority.jwks-uri=http://idp.auth.svc.cluster.local/keys",
                "entra.security.authority.allow-http=true").run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void malformedUrlsAreRejectedWithThePropertyName() {
        runner.withPropertyValues("entra.security.authority.token-endpoint=/oauth2/token")
                .run(context -> assertFailure(context, "entra.security.authority.token-endpoint", "absolute"));
        runner.withPropertyValues("entra.security.authority.userinfo-endpoint=ftp://idp.example/userinfo")
                .run(context -> assertFailure(context, "entra.security.authority.userinfo-endpoint", "https"));
        runner.withPropertyValues("entra.security.authority.metadata-uri=mailto:someone@example.com")
                .run(context -> assertFailure(context, "entra.security.authority.metadata-uri", "absolute"));
        runner.withPropertyValues("entra.security.authority.host=http://login.example.com")
                .run(context -> assertFailure(context, "entra.security.authority.host", "uses http"));
        runner.withPropertyValues("entra.security.authority.authorize-endpoint=http://login.example.com/a")
                .run(context -> assertFailure(context, "entra.security.authority.authorize-endpoint", "uses http"));
        runner.withPropertyValues("entra.security.authority.graph-base-url=http://graph.example.com")
                .run(context -> assertFailure(context, "entra.security.authority.graph-base-url", "uses http"));
    }

    @Test
    void tenantPathAndIssuersAreChecked() {
        runner.withPropertyValues("entra.security.authority.tenant-path=contoso/../other")
                .run(context -> assertFailure(context, "entra.security.authority.tenant-path", "'..'"));
        runner.withPropertyValues("entra.security.authority.tenant-path=contoso?x=1")
                .run(context -> assertFailure(context, "entra.security.authority.tenant-path"));
        runner.withPropertyValues("entra.security.authority.issuers[0]=https://ok", "entra.security.authority.issuers[1]= ")
                .run(context -> assertFailure(context, "entra.security.authority.issuers[1] must not be blank"));
    }

    @Test
    void domainTenantIsFineWithDiscoveryOrAuthorityIssuers() {
        runner.withPropertyValues("entra.security.tenant-id=contoso.onmicrosoft.com",
                "entra.security.authority.issuers=https://login.microsoftonline.com/x/v2.0")
                .run(context -> assertThat(context).hasNotFailed());
        runner.withPropertyValues("entra.security.tenant-id=contoso.onmicrosoft.com",
                "entra.security.authority.discovery.enabled=true", "entra.security.authority.discovery.required=false",
                "entra.security.authority.host=http://localhost:1")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void unreachableRequiredDiscoveryFailsStartup() {
        runner.withPropertyValues("entra.security.authority.metadata-uri=http://localhost:1/.well-known/openid-configuration")
                .run(context -> assertFailure(context, "OIDC discovery from http://localhost:1"));
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
