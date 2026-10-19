package io.github.rmkrdev.entra.security.autoconfigure;

import java.time.Clock;
import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
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

import io.github.rmkrdev.entra.security.autoconfigure.keyvault.KeyVaultCredentialFactory;
import io.github.rmkrdev.entra.security.autoconfigure.metrics.ObservingJwtDecoder;
import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.graph.CachingGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.graph.GraphGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.graph.GroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.introspect.TokenIntrospector;
import io.github.rmkrdev.entra.security.core.jwt.AuthenticationCache;
import io.github.rmkrdev.entra.security.core.jwt.EntraJwtAuthenticationConverter;
import io.github.rmkrdev.entra.security.core.jwt.EntraJwtDecoders;
import io.github.rmkrdev.entra.security.core.jwt.EntraTokenClassifier;
import io.github.rmkrdev.entra.security.core.jwt.SafeClaimLogger;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsAccessDeniedHandler;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsAuthenticationEntryPoint;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsWriter;

/**
 * Auto-configuration that turns a Spring Boot servlet application into an Entra ID resource server.
 * <p>
 * The configuration, JWKS source, token providers, classifier and authority mapper are shared with the
 * reactive stack ({@link EntraReactiveSecurityAutoConfiguration}); the servlet-specific beans are skipped in
 * reactive web applications.
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

    /**
     * The authority endpoints, resolved once from {@code entra.security.authority.*} and, when enabled, the OIDC
     * discovery document.
     */
    @Bean
    @ConditionalOnMissingBean
    public EntraEndpoints entraEndpoints(EntraSecurityProperties properties) {
        return EntraEndpoints.resolve(properties, EntraTokenProviders.defaultRestClient(properties));
    }

    @Bean
    @ConditionalOnMissingBean
    public EntraTokenProviders entraTokenProviders(EntraSecurityProperties properties, Environment environment,
            ObjectProvider<EntraSecurityObservations> observations,
            ObjectProvider<KeyVaultCredentialFactory> keyVaultCredentials, EntraEndpoints endpoints) {
        return new EntraTokenProviders(properties, environment, EntraTokenProviders.defaultRestClient(properties),
                Clock.systemUTC(), observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP),
                keyVaultCredentials.getIfAvailable(), endpoints);
    }

    @Bean
    @ConditionalOnMissingBean(name = "entraJwkSource")
    public JWKSource<SecurityContext> entraJwkSource(EntraSecurityProperties properties, EntraEndpoints endpoints,
            ObjectProvider<EntraSecurityObservations> observations) {
        return EntraJwtDecoders.refreshingJwkSource(endpoints.jwksUri(), properties.getCache().getJwksTtl(),
                properties.getHttp().getConnectTimeout(), properties.getHttp().getReadTimeout(),
                properties.getCache().getJwksRefreshAhead(),
                observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP));
    }

    /**
     * Loads the signing keys while the application starts, so no request waits for the JWKS.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "cache.jwks-prewarm",
            havingValue = "true", matchIfMissing = true)
    public EntraJwksWarmer entraJwksWarmer(ObjectProvider<JWKSource<SecurityContext>> entraJwkSource,
            EntraSecurityProperties properties) {
        return new EntraJwksWarmer(entraJwkSource, properties);
    }

    /** The per-token principal and role-mapping cache shared by the servlet and reactive converters. */
    @Bean
    @ConditionalOnMissingBean
    public AuthenticationCache entraAuthenticationCache(EntraSecurityProperties properties) {
        return new AuthenticationCache(properties.getCache().getAuthenticationTtl(),
                properties.getCache().getAuthenticationMaxEntries(), Clock.systemUTC());
    }

    /**
     * The remote token check for {@code entra.security.validation.mode} introspection and hybrid, with its cache
     * and circuit breaker. Not created in the default jwks mode.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnExpression("'${entra.security.validation.mode:jwks}'.toLowerCase() != 'jwks'")
    public TokenIntrospector entraTokenIntrospector(EntraSecurityProperties properties, EntraEndpoints endpoints,
            ObjectProvider<EntraTokenProviders> tokenProviders, ObjectProvider<EntraSecurityObservations> observations) {
        boolean bearer = properties.getValidation().getIntrospection().getAuthMethod()
                == EntraSecurityProperties.IntrospectionAuthMethod.BEARER;
        EntraTokenProvider appTokens = bearer ? tokenProviders.getObject().applicationTokenProvider() : null;
        return EntraValidation.introspector(properties, endpoints, appTokens, Clock.systemUTC(),
                observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP));
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
                .groupRoleMappings(properties.resolveGroupRoleMappings())
                .appRoleMappings(properties.resolveAppRoleMappings())
                .clientRoleMappings(properties.resolveClientRoleMappings())
                .includeUserRolesClaim(properties.getUser().isIncludeRolesClaim())
                .includeScopes(properties.getUser().isIncludeScopes())
                .mapUnmappedAppRoles(properties.getService().isMapUnmappedAppRoles())
                .defaultUserRoles(properties.getUser().getDefaultRoles())
                .defaultServiceRoles(properties.getService().getDefaultRoles())
                .build();
    }

    /**
     * The servlet resource server: the blocking decoder, converter and problem-details handlers. Skipped in
     * reactive web applications, which get {@link EntraReactiveSecurityAutoConfiguration} instead.
     */
    @Configuration(proxyBeanMethods = false)
    @Conditional(OnNotReactiveWebApplicationCondition.class)
    static class EntraServletResourceServerConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public JwtDecoder entraJwtDecoder(JWKSource<SecurityContext> entraJwkSource,
                EntraSecurityProperties properties, EntraEndpoints endpoints,
                ObjectProvider<TokenIntrospector> introspector,
                ObjectProvider<EntraSecurityObservations> observations) {
            JwtDecoder decoder = EntraValidation.decoder(properties, endpoints, entraJwkSource,
                    introspector.getIfAvailable());
            return ObservingJwtDecoder.wrap(decoder,
                    observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP));
        }

        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "graph.overage-enabled",
                havingValue = "true")
        public GroupMembershipResolver entraGroupMembershipResolver(EntraSecurityProperties properties,
                EntraEndpoints endpoints, EntraTokenProviders tokenProviders,
                ObjectProvider<EntraSecurityObservations> observations) {
            EntraSecurityProperties.Graph graph = properties.getGraph();
            GraphGroupMembershipResolver graphResolver = new GraphGroupMembershipResolver(
                    EntraTokenProviders.defaultRestClient(properties), tokenProviders.applicationTokenProvider(),
                    endpoints.graphBaseUrl(), graph.getScope(), graph.getMaxPages(),
                    observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP));
            return new CachingGroupMembershipResolver(graphResolver, graph.getCacheTtl(),
                    graph.getCacheMaxEntries());
        }

        @Bean
        @ConditionalOnMissingBean
        public EntraJwtAuthenticationConverter entraJwtAuthenticationConverter(EntraTokenClassifier classifier,
                EntraAuthorityMapper mapper, ObjectProvider<GroupMembershipResolver> groupResolver,
                EntraSecurityProperties properties, ObjectProvider<EntraSecurityObservations> observations,
                ObjectProvider<AuthenticationCache> cache) {
            return new EntraJwtAuthenticationConverter(classifier, mapper, groupResolver.getIfAvailable(),
                    properties.getService().isRequireKnownClient(),
                    new SafeClaimLogger(properties.getLogging().isLogClaims()),
                    observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP))
                    .withCache(cache.getIfAvailable());
        }

        @Bean
        @ConditionalOnMissingBean
        public ProblemDetailsWriter entraProblemDetailsWriter(ObjectProvider<ObjectMapper> objectMapper) {
            return new ProblemDetailsWriter(objectMapper.getIfAvailable(ObjectMapper::new));
        }

        @Bean
        @ConditionalOnMissingBean
        public ProblemDetailsAuthenticationEntryPoint entraAuthenticationEntryPoint(ProblemDetailsWriter writer,
                ObjectProvider<EntraSecurityObservations> observations) {
            return new ProblemDetailsAuthenticationEntryPoint(writer,
                    observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP));
        }

        @Bean
        @ConditionalOnMissingBean
        public ProblemDetailsAccessDeniedHandler entraAccessDeniedHandler(ProblemDetailsWriter writer) {
            return new ProblemDetailsAccessDeniedHandler(writer);
        }

        @Bean
        @ConditionalOnMissingBean
        public EntraHttpSecurity entraHttpSecurity(JwtDecoder jwtDecoder,
                EntraJwtAuthenticationConverter converter, ProblemDetailsAuthenticationEntryPoint entryPoint,
                ProblemDetailsAccessDeniedHandler accessDeniedHandler, EntraSecurityProperties properties) {
            List<String> publicPaths = properties.getPublicPaths();
            return new EntraHttpSecurity(jwtDecoder, converter, entryPoint, accessDeniedHandler, publicPaths);
        }
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
    @Conditional(OnNotReactiveWebApplicationCondition.class)
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
