package io.github.rmkrdev.entra.security.autoconfigure;

import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.graph.CachingGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.graph.GraphGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.graph.GroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.jwt.EntraJwtAuthenticationConverter;
import io.github.rmkrdev.entra.security.core.jwt.EntraJwtDecoders;
import io.github.rmkrdev.entra.security.core.jwt.EntraTokenClassifier;
import io.github.rmkrdev.entra.security.core.jwt.SafeClaimLogger;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsAccessDeniedHandler;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsAuthenticationEntryPoint;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsWriter;

/**
 * Auto-configuration that turns a Spring Boot servlet application into an Entra ID resource server.
 */
@AutoConfiguration(beforeName = {
        "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration" })
@ConditionalOnClass({ JwtDecoder.class, SecurityFilterChain.class })
@ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(EntraSecurityProperties.class)
public class EntraSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public EntraTokenProviders entraTokenProviders(EntraSecurityProperties properties, Environment environment) {
        return new EntraTokenProviders(properties, environment);
    }

    @Bean
    @ConditionalOnMissingBean(name = "entraJwkSource")
    public JWKSource<SecurityContext> entraJwkSource(EntraSecurityProperties properties) {
        return EntraJwtDecoders.jwkSource(properties.resolveJwkSetUri(), properties.getCache().getJwksTtl(),
                properties.getHttp().getReadTimeout());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder entraJwtDecoder(JWKSource<SecurityContext> entraJwkSource, EntraSecurityProperties properties) {
        String tenant = properties.isRequireTenantMatch()
                && EntraSecurityProperties.GUID.matcher(properties.getTenantId()).matches()
                        ? properties.getTenantId() : null;
        return EntraJwtDecoders.create(entraJwkSource, properties.resolveIssuers(), properties.resolveAudiences(),
                tenant, properties.getClockSkew());
    }

    @Bean
    @ConditionalOnMissingBean
    public EntraTokenClassifier entraTokenClassifier() {
        return new EntraTokenClassifier();
    }

    @Bean
    @ConditionalOnMissingBean
    public EntraAuthorityMapper entraAuthorityMapper(EntraSecurityProperties properties) {
        return EntraAuthorityMapper.builder()
                .groupRoleMappings(properties.getGroupRoleMappings())
                .appRoleMappings(properties.getAppRoleMappings())
                .clientRoleMappings(properties.getClientRoleMappings())
                .includeUserRolesClaim(properties.getUser().isIncludeRolesClaim())
                .includeScopes(properties.getUser().isIncludeScopes())
                .mapUnmappedAppRoles(properties.getService().isMapUnmappedAppRoles())
                .defaultUserRoles(properties.getUser().getDefaultRoles())
                .defaultServiceRoles(properties.getService().getDefaultRoles())
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "graph.overage-enabled",
            havingValue = "true")
    public GroupMembershipResolver entraGroupMembershipResolver(EntraSecurityProperties properties,
            EntraTokenProviders tokenProviders) {
        EntraSecurityProperties.Graph graph = properties.getGraph();
        GraphGroupMembershipResolver graphResolver = new GraphGroupMembershipResolver(
                EntraTokenProviders.defaultRestClient(properties), tokenProviders.applicationTokenProvider(),
                graph.getBaseUrl(), graph.getScope(), graph.getMaxPages());
        return new CachingGroupMembershipResolver(graphResolver, graph.getCacheTtl(), graph.getCacheMaxEntries());
    }

    @Bean
    @ConditionalOnMissingBean
    public EntraJwtAuthenticationConverter entraJwtAuthenticationConverter(EntraTokenClassifier classifier,
            EntraAuthorityMapper mapper, ObjectProvider<GroupMembershipResolver> groupResolver,
            EntraSecurityProperties properties) {
        return new EntraJwtAuthenticationConverter(classifier, mapper, groupResolver.getIfAvailable(),
                properties.getService().isRequireKnownClient(),
                new SafeClaimLogger(properties.getLogging().isLogClaims()));
    }

    @Bean
    @ConditionalOnMissingBean
    public ProblemDetailsWriter entraProblemDetailsWriter(ObjectProvider<ObjectMapper> objectMapper) {
        return new ProblemDetailsWriter(objectMapper.getIfAvailable(ObjectMapper::new));
    }

    @Bean
    @ConditionalOnMissingBean
    public ProblemDetailsAuthenticationEntryPoint entraAuthenticationEntryPoint(ProblemDetailsWriter writer) {
        return new ProblemDetailsAuthenticationEntryPoint(writer);
    }

    @Bean
    @ConditionalOnMissingBean
    public ProblemDetailsAccessDeniedHandler entraAccessDeniedHandler(ProblemDetailsWriter writer) {
        return new ProblemDetailsAccessDeniedHandler(writer);
    }

    @Bean
    @ConditionalOnMissingBean
    public EntraHttpSecurity entraHttpSecurity(JwtDecoder jwtDecoder, EntraJwtAuthenticationConverter converter,
            ProblemDetailsAuthenticationEntryPoint entryPoint, ProblemDetailsAccessDeniedHandler accessDeniedHandler,
            EntraSecurityProperties properties) {
        List<String> publicPaths = properties.getPublicPaths();
        return new EntraHttpSecurity(jwtDecoder, converter, entryPoint, accessDeniedHandler, publicPaths);
    }

    /**
     * The default filter chain; backs off when the application defines its own.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    static class EntraSecurityFilterChainConfiguration {

        @Bean
        @Order(SecurityProperties.BASIC_AUTH_ORDER)
        SecurityFilterChain entraSecurityFilterChain(HttpSecurity http, EntraHttpSecurity entraHttpSecurity)
                throws Exception {
            return entraHttpSecurity.configure(http).build();
        }
    }

    /**
     * Enables {@code @Secured}, {@code @PreAuthorize} and {@code @RolesAllowed} by default.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "method-security.enabled",
            havingValue = "true", matchIfMissing = true)
    @EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
    static class EntraMethodSecurityConfiguration {
    }

    /**
     * Lets controllers declare {@code EntraPrincipal} parameters.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass(WebMvcConfigurer.class)
    static class EntraWebMvcConfiguration implements WebMvcConfigurer {

        @Override
        public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
            resolvers.add(new EntraPrincipalArgumentResolver());
        }
    }
}
