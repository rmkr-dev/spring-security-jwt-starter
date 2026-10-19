package io.github.rmkrdev.entra.security.autoconfigure;


import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.rmkrdev.entra.security.autoconfigure.metrics.ObservingJwtDecoder;
import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.graph.CachingReactiveGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.graph.GroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.graph.ReactiveGraphGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.graph.ReactiveGroupMembershipResolver;
import io.github.rmkrdev.entra.security.core.introspect.TokenIntrospector;
import io.github.rmkrdev.entra.security.core.jwt.AuthenticationCache;
import io.github.rmkrdev.entra.security.core.jwt.EntraReactiveJwtDecoder;
import io.github.rmkrdev.entra.security.core.jwt.EntraTokenClassifier;
import io.github.rmkrdev.entra.security.core.jwt.ReactiveEntraJwtAuthenticationConverter;
import io.github.rmkrdev.entra.security.core.jwt.SafeClaimLogger;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.web.server.ServerProblemDetailsAccessDeniedHandler;
import io.github.rmkrdev.entra.security.core.web.server.ServerProblemDetailsAuthenticationEntryPoint;
import io.github.rmkrdev.entra.security.core.web.server.ServerProblemDetailsWriter;
import reactor.core.publisher.Mono;

/**
 * Auto-configuration that turns a Spring Boot WebFlux application into an Entra ID resource server, with
 * the same token validation, role mapping, group-overage lookup and problem-details responses as the
 * servlet stack.
 * <p>
 * Active only in reactive web applications. The shared beans (configuration, JWKS source, token providers,
 * classifier, authority mapper) come from {@link EntraSecurityAutoConfiguration}.
 */
@AutoConfiguration(after = EntraSecurityAutoConfiguration.class, beforeName = {
        "org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.reactive.ReactiveUserDetailsServiceAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.oauth2.resource.reactive.ReactiveOAuth2ResourceServerAutoConfiguration" })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass({ ReactiveJwtDecoder.class, SecurityWebFilterChain.class, ServerHttpSecurity.class, Mono.class })
@ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(EntraSecurityProperties.class)
public class EntraReactiveSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ReactiveJwtDecoder entraReactiveJwtDecoder(JWKSource<SecurityContext> entraJwkSource,
            EntraSecurityProperties properties, EntraEndpoints endpoints,
            ObjectProvider<TokenIntrospector> introspector,
            ObjectProvider<EntraSecurityObservations> observations) {
        JwtDecoder decoder = EntraValidation.decoder(properties, endpoints, entraJwkSource,
                introspector.getIfAvailable());
        return new EntraReactiveJwtDecoder(ObservingJwtDecoder.wrap(decoder,
                observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP)));
    }

    @Bean
    @ConditionalOnMissingBean({ ReactiveGroupMembershipResolver.class, GroupMembershipResolver.class })
    @ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "graph.overage-enabled",
            havingValue = "true")
    public ReactiveGroupMembershipResolver entraReactiveGroupMembershipResolver(EntraSecurityProperties properties,
            EntraEndpoints endpoints, EntraTokenProviders tokenProviders,
            ObjectProvider<EntraSecurityObservations> observations) {
        EntraSecurityProperties.Graph graph = properties.getGraph();
        ReactiveGraphGroupMembershipResolver graphResolver = new ReactiveGraphGroupMembershipResolver(
                defaultWebClient(properties), tokenProviders.applicationTokenProvider(), endpoints.graphBaseUrl(),
                graph.getScope(), graph.getMaxPages(), properties.getHttp().getReadTimeout(),
                observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP));
        return new CachingReactiveGroupMembershipResolver(graphResolver, graph.getCacheTtl(),
                graph.getCacheMaxEntries());
    }

    /**
     * Uses a {@link ReactiveGroupMembershipResolver} when there is one, otherwise adapts an application-defined
     * blocking {@link GroupMembershipResolver} onto {@code boundedElastic}.
     */
    @Bean
    @ConditionalOnMissingBean
    public ReactiveEntraJwtAuthenticationConverter entraReactiveJwtAuthenticationConverter(
            EntraTokenClassifier classifier, EntraAuthorityMapper mapper,
            ObjectProvider<ReactiveGroupMembershipResolver> reactiveGroupResolver,
            ObjectProvider<GroupMembershipResolver> groupResolver, EntraSecurityProperties properties,
            ObjectProvider<EntraSecurityObservations> observations, ObjectProvider<AuthenticationCache> cache) {
        ReactiveGroupMembershipResolver resolver = reactiveGroupResolver.getIfAvailable(() -> {
            GroupMembershipResolver blocking = groupResolver.getIfAvailable();
            return blocking != null ? ReactiveGroupMembershipResolver.fromBlocking(blocking) : null;
        });
        return new ReactiveEntraJwtAuthenticationConverter(classifier, mapper, resolver,
                properties.getService().isRequireKnownClient(),
                new SafeClaimLogger(properties.getLogging().isLogClaims()),
                observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP))
                .withCache(cache.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public ServerProblemDetailsWriter entraServerProblemDetailsWriter(ObjectProvider<ObjectMapper> objectMapper) {
        return new ServerProblemDetailsWriter(objectMapper.getIfAvailable(ObjectMapper::new));
    }

    @Bean
    @ConditionalOnMissingBean
    public ServerProblemDetailsAuthenticationEntryPoint entraServerAuthenticationEntryPoint(
            ServerProblemDetailsWriter writer, ObjectProvider<EntraSecurityObservations> observations) {
        return new ServerProblemDetailsAuthenticationEntryPoint(writer,
                observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP));
    }

    @Bean
    @ConditionalOnMissingBean
    public ServerProblemDetailsAccessDeniedHandler entraServerAccessDeniedHandler(ServerProblemDetailsWriter writer) {
        return new ServerProblemDetailsAccessDeniedHandler(writer);
    }

    @Bean
    @ConditionalOnMissingBean
    public EntraServerHttpSecurity entraServerHttpSecurity(ReactiveJwtDecoder jwtDecoder,
            ReactiveEntraJwtAuthenticationConverter converter, ServerProblemDetailsAuthenticationEntryPoint entryPoint,
            ServerProblemDetailsAccessDeniedHandler accessDeniedHandler, EntraSecurityProperties properties) {
        return new EntraServerHttpSecurity(jwtDecoder, converter, entryPoint, accessDeniedHandler,
                properties.getPublicPaths());
    }

    /** WebClient for Graph that uses the {@code entra.security.http} timeouts. */
    static WebClient defaultWebClient(EntraSecurityProperties properties) {
        JdkClientHttpConnector connector = new JdkClientHttpConnector(
                EntraTokenProviders.pooledHttpClient(properties.getHttp().getConnectTimeout()));
        connector.setReadTimeout(properties.getHttp().getReadTimeout());
        return WebClient.builder().clientConnector(connector).build();
    }

    /**
     * The default filter chain; backs off when the application defines its own.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingBean(SecurityWebFilterChain.class)
    static class EntraSecurityWebFilterChainConfiguration {

        @Bean
        @Order(SecurityProperties.BASIC_AUTH_ORDER)
        SecurityWebFilterChain entraSecurityWebFilterChain(ServerHttpSecurity http,
                EntraServerHttpSecurity entraServerHttpSecurity) {
            return entraServerHttpSecurity.configure(http).build();
        }
    }

    /**
     * Enables {@code @PreAuthorize}/{@code @PostAuthorize} and {@code @Secured} on reactive methods by default.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "method-security.enabled",
            havingValue = "true", matchIfMissing = true)
    @EnableReactiveMethodSecurity
    @Import(EntraReactiveSecuredConfiguration.class)
    static class EntraReactiveMethodSecurityConfiguration {
    }

    /**
     * Adds {@code @Secured} when the application enables {@code @EnableReactiveMethodSecurity} itself while
     * {@code entra.security.method-security.enabled=false}.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnBean(type = "org.springframework.security.config.annotation.method.configuration."
            + "ReactiveAuthorizationManagerMethodSecurityConfiguration")
    @Import(EntraReactiveSecuredConfiguration.class)
    static class EntraReactiveSecuredSupportConfiguration {
    }

    /**
     * Lets WebFlux controllers declare {@code EntraPrincipal} and {@code Mono<EntraPrincipal>} parameters.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(WebFluxConfigurer.class)
    static class EntraWebFluxConfiguration implements WebFluxConfigurer {

        @Override
        public void configureArgumentResolvers(ArgumentResolverConfigurer configurer) {
            configurer.addCustomResolver(new ReactiveEntraPrincipalArgumentResolver());
        }
    }
}
