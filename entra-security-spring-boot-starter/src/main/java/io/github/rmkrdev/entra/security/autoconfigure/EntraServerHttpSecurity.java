package io.github.rmkrdev.entra.security.autoconfigure;

import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;

import io.github.rmkrdev.entra.security.core.web.server.ReactiveAuthTiming;

import java.util.List;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;

import io.github.rmkrdev.entra.security.core.web.server.ServerProblemDetailsAccessDeniedHandler;
import io.github.rmkrdev.entra.security.core.web.server.ServerProblemDetailsAuthenticationEntryPoint;
import reactor.core.publisher.Mono;

/**
 * Applies the Entra defaults to a WebFlux {@link ServerHttpSecurity}: stateless, CSRF off, public paths open,
 * everything else authenticated with an Entra bearer token, and JSON problem details for 401/403. The
 * reactive counterpart of {@link EntraHttpSecurity}. CSRF stays off because a browser does not attach
 * {@code Authorization} on a cross-site request and this chain has no session cookie.
 * <p>
 * The starter uses it for its default {@code SecurityWebFilterChain}. Services that define their own chain
 * can reuse it:
 *
 * <pre>{@code
 * @Bean
 * SecurityWebFilterChain api(ServerHttpSecurity http, EntraServerHttpSecurity entra) {
 *     http.securityMatcher(pathMatchers("/api/**"));
 *     return entra.configure(http).build();
 * }
 * }</pre>
 */
public class EntraServerHttpSecurity {

    private final ReactiveJwtDecoder jwtDecoder;
    private final Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> converter;
    private final ServerProblemDetailsAuthenticationEntryPoint entryPoint;
    private final ServerProblemDetailsAccessDeniedHandler accessDeniedHandler;
    private final List<String> publicPaths;
    private final ReactiveAuthTiming timing;

    public EntraServerHttpSecurity(ReactiveJwtDecoder jwtDecoder,
            Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> converter,
            ServerProblemDetailsAuthenticationEntryPoint entryPoint,
            ServerProblemDetailsAccessDeniedHandler accessDeniedHandler, List<String> publicPaths) {
        this(jwtDecoder, converter, entryPoint, accessDeniedHandler, publicPaths, null);
    }

    /**
     * @param timing times each exchange's authentication work and records the decision; {@code null} disables it
     */
    public EntraServerHttpSecurity(ReactiveJwtDecoder jwtDecoder,
            Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> converter,
            ServerProblemDetailsAuthenticationEntryPoint entryPoint,
            ServerProblemDetailsAccessDeniedHandler accessDeniedHandler, List<String> publicPaths,
            ReactiveAuthTiming timing) {
        this.timing = timing;
        this.jwtDecoder = jwtDecoder;
        this.converter = converter;
        this.entryPoint = entryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
        this.publicPaths = List.copyOf(publicPaths);
    }

    public ServerHttpSecurity configure(ServerHttpSecurity http) {
        ServerAuthenticationEntryPoint entryPoint = timing == null ? this.entryPoint : timing.wrap(this.entryPoint);
        ServerAccessDeniedHandler accessDeniedHandler = timing == null ? this.accessDeniedHandler
                : timing.wrap(this.accessDeniedHandler);
        if (timing != null) {
            http.addFilterBefore(timing.startFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                    .addFilterAfter(timing.endFilter(), SecurityWebFiltersOrder.AUTHORIZATION);
        }
        // codeql[java/spring-disabled-csrf-protection] Stateless bearer-token chain; no session cookie.
        http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(Customizer.withDefaults())
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .requestCache(cache -> cache.requestCache(NoOpServerRequestCache.getInstance()))
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .authorizeExchange(authorize -> {
                    if (!publicPaths.isEmpty()) {
                        authorize.pathMatchers(publicPaths.toArray(String[]::new)).permitAll();
                    }
                    authorize.anyExchange().authenticated();
                })
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder).jwtAuthenticationConverter(converter))
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler));
        return http;
    }

    public List<String> getPublicPaths() {
        return publicPaths;
    }
}
