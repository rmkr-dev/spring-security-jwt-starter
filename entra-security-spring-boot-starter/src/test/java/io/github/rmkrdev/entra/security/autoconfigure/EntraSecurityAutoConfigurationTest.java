package io.github.rmkrdev.entra.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.http.converter.autoconfigure.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import io.github.rmkrdev.entra.security.core.graph.GroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.jwt.EntraJwtAuthenticationConverter;

class EntraSecurityAutoConfigurationTest {

    private static final String TENANT = "entra.security.tenant-id=11111111-1111-1111-1111-111111111111";
    private static final String CLIENT = "entra.security.client-id=22222222-2222-2222-2222-222222222222";

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EntraSecurityAutoConfiguration.class,
                    EntraOutboundAutoConfiguration.class, SecurityAutoConfiguration.class,
                    ServletWebSecurityAutoConfiguration.class,
                    UserDetailsServiceAutoConfiguration.class, OAuth2ResourceServerAutoConfiguration.class,
                    WebMvcAutoConfiguration.class, JacksonAutoConfiguration.class,
                    HttpMessageConvertersAutoConfiguration.class));

    @Test
    void validConfigurationCreatesSecurityBeans() {
        runner.withPropertyValues(TENANT, CLIENT).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(JwtDecoder.class);
            assertThat(context).hasSingleBean(EntraJwtAuthenticationConverter.class);
            assertThat(context).hasBean("entraSecurityFilterChain");
            assertThat(context).doesNotHaveBean(UserDetailsService.class);
            assertThat(context).doesNotHaveBean(GroupMembershipResolver.class);
            assertThat(context).hasSingleBean(EntraOutboundClients.class);
            EntraSecurityProperties properties = context.getBean(EntraSecurityProperties.class);
            assertThat(properties.resolveIssuers()).containsExactly(
                    "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
                    "https://sts.windows.net/11111111-1111-1111-1111-111111111111/");
            assertThat(properties.resolveAudiences()).containsExactly(
                    "api://22222222-2222-2222-2222-222222222222", "22222222-2222-2222-2222-222222222222");
            assertThat(properties.resolveJwkSetUri()).hasToString(
                    "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys");
        });
    }

    @Test
    void performanceDefaultsCacheValidationAndPrewarmKeys() {
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.authority.jwks-uri=http://127.0.0.1:9/keys",
                "entra.security.authority.allow-http=true").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(JwtDecoder.class)).isInstanceOf(
                    io.github.rmkrdev.entra.security.core.jwt.CachingJwtDecoder.class);
            assertThat(context.getBean("entraJwkSource")).isInstanceOf(
                    io.github.rmkrdev.entra.security.core.jwt.EntraJwkSource.class);
            assertThat(context.getBean(EntraJwksWarmer.class).getLoadedKeys()).isEqualTo(-1);
            assertThat(context).hasSingleBean(io.github.rmkrdev.entra.security.core.jwt.AuthenticationCache.class);
            EntraSecurityProperties.Http http = context.getBean(EntraSecurityProperties.class).getHttp();
            assertThat(http.getConnectTimeout()).hasSeconds(2);
            assertThat(http.getReadTimeout()).hasSeconds(3);
        });
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.cache.validated-token-ttl=0",
                "entra.security.cache.jwks-prewarm=false").run(context -> {
            assertThat(context.getBean(JwtDecoder.class)).isNotInstanceOf(
                    io.github.rmkrdev.entra.security.core.jwt.CachingJwtDecoder.class);
            assertThat(context).doesNotHaveBean(EntraJwksWarmer.class);
        });
    }

    @Test
    void missingTenantAndClientFailFastWithClearMessage() {
        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(rootMessage(context.getStartupFailure()))
                    .contains("tenantId")
                    .contains("must be set to your Microsoft Entra directory (tenant) ID")
                    .contains("clientId")
                    .contains("application (client) ID");
        });
    }

    @Test
    void multiTenantAuthorityRejected() {
        runner.withPropertyValues("entra.security.tenant-id=common", CLIENT).run(context -> {
            assertThat(context).hasFailed();
            assertThat(rootMessage(context.getStartupFailure())).contains("'common'");
        });
    }

    @Test
    void domainTenantRequiresExplicitIssuers() {
        runner.withPropertyValues("entra.security.tenant-id=contoso.onmicrosoft.com", CLIENT).run(context -> {
            assertThat(context).hasFailed();
            assertThat(rootMessage(context.getStartupFailure())).contains("tenant GUID");
        });
        runner.withPropertyValues("entra.security.tenant-id=contoso.onmicrosoft.com", CLIENT,
                "entra.security.issuers=https://sts.windows.net/11111111-1111-1111-1111-111111111111/")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void graphOverageRequiresCredential() {
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.graph.overage-enabled=true").run(context -> {
            assertThat(context).hasFailed();
            assertThat(rootMessage(context.getStartupFailure())).contains("entra.security.credential.type");
        });
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.graph.overage-enabled=true",
                "entra.security.credential.type=client-secret").run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootMessage(context.getStartupFailure())).contains("credential.client-secret");
                });
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.graph.overage-enabled=true",
                "entra.security.credential.type=client-secret", "entra.security.credential.client-secret=x")
                .run(context -> assertThat(context).hasSingleBean(GroupMembershipResolver.class));
    }

    @Test
    void outboundClientNeedsScopeAndCredential() {
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.outbound.clients.orders.scope=api://o/.default")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootMessage(context.getStartupFailure())).contains("outbound.clients");
                });
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.outbound.clients.orders.credential.type=client-secret",
                "entra.security.outbound.clients.orders.credential.client-secret=x").run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootMessage(context.getStartupFailure())).contains("scope");
                });
    }

    @Test
    void workloadIdentityWithoutTokenFileFailsAtStartup() {
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.credential.type=workload-identity",
                "entra.security.outbound.clients.orders.scope=api://o/.default").run(context -> {
                    if (System.getenv("AZURE_FEDERATED_TOKEN_FILE") == null) {
                        assertThat(context).hasFailed();
                        assertThat(rootMessage(context.getStartupFailure())).contains("AZURE_FEDERATED_TOKEN_FILE");
                    }
                });
    }

    @Test
    void backsOffWhenApplicationDefinesItsOwnFilterChain() {
        runner.withPropertyValues(TENANT, CLIENT).withUserConfiguration(CustomChain.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean("entraSecurityFilterChain");
            assertThat(context).hasBean("customChain");
            assertThat(context).hasSingleBean(EntraHttpSecurity.class);
        });
    }

    @Test
    void canBeDisabled() {
        runner.withPropertyValues("entra.security.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(EntraSecurityProperties.class);
            assertThat(context).doesNotHaveBean(EntraHttpSecurity.class);
        });
    }

    private static String rootMessage(Throwable failure) {
        StringBuilder message = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            message.append(t.getMessage()).append('\n');
        }
        return message.toString();
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomChain {

        @Bean
        SecurityFilterChain customChain(HttpSecurity http, EntraHttpSecurity entra) throws Exception {
            return entra.configure(http).build();
        }
    }
}
