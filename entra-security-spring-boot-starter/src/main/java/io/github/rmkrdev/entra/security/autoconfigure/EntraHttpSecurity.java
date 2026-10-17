package io.github.rmkrdev.entra.security.autoconfigure;

import java.util.List;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import io.github.rmkrdev.entra.security.core.jwt.EntraJwtAuthenticationConverter;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsAccessDeniedHandler;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsAuthenticationEntryPoint;

import jakarta.servlet.DispatcherType;

/**
 * Applies the Entra defaults to an {@link HttpSecurity}: stateless, CSRF off, public paths open,
 * everything else authenticated with an Entra bearer token, and JSON problem details for 401/403.
 * <p>
 * The starter uses it for its default filter chain. Services that define their own
 * {@code SecurityFilterChain} can reuse it:
 *
 * <pre>{@code
 * @Bean
 * SecurityFilterChain api(HttpSecurity http, EntraHttpSecurity entra) throws Exception {
 *     entra.configure(http);
 *     return http.build();
 * }
 * }</pre>
 */
public class EntraHttpSecurity {

    private final JwtDecoder jwtDecoder;
    private final EntraJwtAuthenticationConverter converter;
    private final ProblemDetailsAuthenticationEntryPoint entryPoint;
    private final ProblemDetailsAccessDeniedHandler accessDeniedHandler;
    private final List<String> publicPaths;

    public EntraHttpSecurity(JwtDecoder jwtDecoder, EntraJwtAuthenticationConverter converter,
            ProblemDetailsAuthenticationEntryPoint entryPoint, ProblemDetailsAccessDeniedHandler accessDeniedHandler,
            List<String> publicPaths) {
        this.jwtDecoder = jwtDecoder;
        this.converter = converter;
        this.entryPoint = entryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
        this.publicPaths = List.copyOf(publicPaths);
    }

    public HttpSecurity configure(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> {
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> {
                    authorize.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll();
                    if (!publicPaths.isEmpty()) {
                        authorize.requestMatchers(publicPaths.toArray(String[]::new)).permitAll();
                    }
                    authorize.anyRequest().authenticated();
                })
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(jwt -> jwt.decoder(jwtDecoder).jwtAuthenticationConverter(converter))
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
