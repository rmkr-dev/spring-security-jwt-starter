package io.github.rmkrdev.entra.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.http.converter.autoconfigure.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.reactive.ReactiveOAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.reactive.ReactiveWebSecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.ReactiveUserDetailsServiceAutoConfiguration;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.webflux.autoconfigure.WebFluxAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;

import io.github.rmkrdev.entra.security.core.graph.CachingReactiveGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.graph.GroupMembership;
import io.github.rmkrdev.entra.security.core.graph.GroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.graph.ReactiveGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.jwt.EntraJwtAuthenticationConverter;
import io.github.rmkrdev.entra.security.core.jwt.EntraReactiveJwtDecoder;
import io.github.rmkrdev.entra.security.core.jwt.ReactiveEntraJwtAuthenticationConverter;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsAuthenticationEntryPoint;
import io.github.rmkrdev.entra.security.core.web.server.ServerProblemDetailsAccessDeniedHandler;
import io.github.rmkrdev.entra.security.core.web.server.ServerProblemDetailsAuthenticationEntryPoint;

class EntraReactiveSecurityAutoConfigurationTest {

    private static final String TENANT = "entra.security.tenant-id=11111111-1111-1111-1111-111111111111";
    private static final String CLIENT = "entra.security.client-id=22222222-2222-2222-2222-222222222222";

    private static final AutoConfigurations CONFIGURATIONS = AutoConfigurations.of(
            EntraSecurityAutoConfiguration.class, EntraReactiveSecurityAutoConfiguration.class,
            EntraOutboundAutoConfiguration.class, ReactiveWebSecurityAutoConfiguration.class,
            ReactiveUserDetailsServiceAutoConfiguration.class, ReactiveOAuth2ResourceServerAutoConfiguration.class,
            WebFluxAutoConfiguration.class, JacksonAutoConfiguration.class);

    private final ReactiveWebApplicationContextRunner runner = new ReactiveWebApplicationContextRunner()
            .withConfiguration(CONFIGURATIONS);

    @Test
    void reactiveApplicationGetsTheReactiveResourceServer() {
        runner.withPropertyValues(TENANT, CLIENT).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).getBean(ReactiveJwtDecoder.class).isInstanceOf(EntraReactiveJwtDecoder.class);
            assertThat(context).hasSingleBean(ReactiveEntraJwtAuthenticationConverter.class);
            assertThat(context).hasSingleBean(ServerProblemDetailsAuthenticationEntryPoint.class);
            assertThat(context).hasSingleBean(ServerProblemDetailsAccessDeniedHandler.class);
            assertThat(context).hasSingleBean(EntraServerHttpSecurity.class);
            assertThat(context).hasBean("entraSecurityWebFilterChain");
            assertThat(context).hasBean("entraReactiveSecuredAuthorizationMethodInterceptor");
            assertThat(context).doesNotHaveBean(ReactiveUserDetailsService.class);
            assertThat(context).doesNotHaveBean(ReactiveGroupMembershipResolver.class);
            assertThat(context).hasSingleBean(EntraOutboundClients.class);
            assertThat(context.getBean(EntraServerHttpSecurity.class).getPublicPaths())
                    .contains("/actuator/health");
        });
    }

    @Test
    void servletBeansStayOutOfReactiveApplications() {
        runner.withPropertyValues(TENANT, CLIENT).run(context -> {
            assertThat(context).doesNotHaveBean(JwtDecoder.class);
            assertThat(context).doesNotHaveBean(EntraJwtAuthenticationConverter.class);
            assertThat(context).doesNotHaveBean(ProblemDetailsAuthenticationEntryPoint.class);
            assertThat(context).doesNotHaveBean(EntraHttpSecurity.class);
            assertThat(context).doesNotHaveBean(SecurityFilterChain.class);
            assertThat(context).doesNotHaveBean(
                    "org.springframework.security.config.annotation.method.configuration."
                            + "PrePostMethodSecurityConfiguration");
        });
    }

    @Test
    void servletAndNonWebApplicationsDoNotGetReactiveBeans() {
        AutoConfigurations servlet = AutoConfigurations.of(EntraSecurityAutoConfiguration.class,
                EntraReactiveSecurityAutoConfiguration.class, SecurityAutoConfiguration.class,
                ServletWebSecurityAutoConfiguration.class,
                OAuth2ResourceServerAutoConfiguration.class, WebMvcAutoConfiguration.class,
                JacksonAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class);
        new WebApplicationContextRunner().withConfiguration(servlet).withPropertyValues(TENANT, CLIENT)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(JwtDecoder.class);
                    assertThat(context).doesNotHaveBean(ReactiveJwtDecoder.class);
                    assertThat(context).doesNotHaveBean(ReactiveEntraJwtAuthenticationConverter.class);
                    assertThat(context).doesNotHaveBean(SecurityWebFilterChain.class);
                });
        new ApplicationContextRunner().withConfiguration(servlet).withPropertyValues(TENANT, CLIENT)
                .run(context -> {
                    assertThat(context).hasSingleBean(EntraJwtAuthenticationConverter.class);
                    assertThat(context).doesNotHaveBean(ReactiveEntraJwtAuthenticationConverter.class);
                });
    }

    @Test
    void overageUsesTheReactiveGraphResolver() {
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.graph.overage-enabled=true",
                "entra.security.credential.type=client-secret", "entra.security.credential.client-secret=s")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).getBean(ReactiveGroupMembershipResolver.class)
                            .isInstanceOf(CachingReactiveGroupMembershipResolver.class);
                    assertThat(context).doesNotHaveBean(GroupMembershipResolver.class);
                });
    }

    @Test
    void applicationBlockingGroupResolverIsAdapted() {
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.graph.overage-enabled=true",
                "entra.security.credential.type=client-secret", "entra.security.credential.client-secret=s")
                .withUserConfiguration(BlockingResolverConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(ReactiveGroupMembershipResolver.class);
                    assertThat(context).hasSingleBean(ReactiveEntraJwtAuthenticationConverter.class);
                });
    }

    @Test
    void backsOffWhenApplicationDefinesItsOwnFilterChain() {
        runner.withPropertyValues(TENANT, CLIENT).withUserConfiguration(CustomChainConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean("entraSecurityWebFilterChain");
                    assertThat(context).hasBean("customChain");
                    assertThat(context).hasSingleBean(EntraServerHttpSecurity.class);
                });
    }

    @Test
    void methodSecurityCanBeTurnedOffUnlessTheApplicationEnablesIt() {
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.method-security.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean("entraReactiveSecuredAuthorizationMethodInterceptor");
        });
        runner.withPropertyValues(TENANT, CLIENT, "entra.security.method-security.enabled=false")
                .withUserConfiguration(OwnReactiveMethodSecurity.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasBean("entraReactiveSecuredAuthorizationMethodInterceptor");
                });
    }

    @Test
    void validationAppliesToReactiveApplicationsToo() {
        runner.withPropertyValues("entra.security.tenant-id=common", CLIENT).run(context -> {
            assertThat(context).hasFailed();
            Throwable root = context.getStartupFailure();
            while (root.getCause() != null) {
                root = root.getCause();
            }
            assertThat(root.getMessage()).contains("'common'");
        });
    }

    @Test
    void canBeDisabled() {
        runner.withPropertyValues("entra.security.enabled=false").run(context -> {
            assertThat(context).doesNotHaveBean(ReactiveEntraJwtAuthenticationConverter.class);
            assertThat(context).doesNotHaveBean("entraSecurityWebFilterChain");
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class BlockingResolverConfiguration {

        @Bean
        GroupMembershipResolver customResolver() {
            return (tenantId, objectId) -> List.of(new GroupMembership("g", null));
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomChainConfiguration {

        @Bean
        SecurityWebFilterChain customChain(ServerHttpSecurity http, EntraServerHttpSecurity entra) {
            return entra.configure(http).build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableReactiveMethodSecurity
    static class OwnReactiveMethodSecurity {
    }
}
