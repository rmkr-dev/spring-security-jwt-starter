package io.github.rmkrdev.entra.security.autoconfigure;

import org.springframework.core.MethodParameter;
import org.springframework.core.ResolvableType;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.reactive.result.method.HandlerMethodArgumentResolver;
import org.springframework.web.server.ServerWebExchange;

import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import io.github.rmkrdev.entra.security.core.principal.ReactiveEntraPrincipals;
import reactor.core.publisher.Mono;

/**
 * Resolves {@link EntraPrincipal} and {@code Mono<EntraPrincipal>} WebFlux controller parameters from the
 * reactive security context, without needing {@code @AuthenticationPrincipal}. A plain {@code EntraPrincipal}
 * resolves to {@code null} (and a {@code Mono} completes empty) for anonymous requests on public paths.
 */
public class ReactiveEntraPrincipalArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        if (EntraPrincipal.class.equals(parameter.getParameterType())) {
            return true;
        }
        return Mono.class.equals(parameter.getParameterType()) && EntraPrincipal.class.equals(
                ResolvableType.forMethodParameter(parameter).getGeneric(0).resolve());
    }

    @Override
    public Mono<Object> resolveArgument(MethodParameter parameter, BindingContext bindingContext,
            ServerWebExchange exchange) {
        Mono<EntraPrincipal> principal = ReactiveEntraPrincipals.current();
        if (Mono.class.equals(parameter.getParameterType())) {
            return Mono.just(principal);
        }
        return principal.cast(Object.class);
    }
}
