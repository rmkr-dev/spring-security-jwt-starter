package io.github.rmkrdev.entra.security.core.principal;

import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;

import reactor.core.publisher.Mono;

/**
 * Access to the current {@link EntraPrincipal} on WebFlux, where {@link EntraPrincipals#current()} does not
 * apply because the security context lives in the Reactor context rather than a thread-local.
 */
public final class ReactiveEntraPrincipals {

    private ReactiveEntraPrincipals() {
    }

    /**
     * The principal of the current request, or empty when it was not authenticated with an Entra token.
     */
    public static Mono<EntraPrincipal> current() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .flatMap(authentication -> Mono.justOrEmpty(EntraPrincipals.from(authentication)));
    }

    /**
     * The principal of the current request; an {@link IllegalStateException} error when there is none.
     */
    public static Mono<EntraPrincipal> require() {
        return current().switchIfEmpty(Mono.error(() -> new IllegalStateException(
                "No authenticated EntraPrincipal in the current security context")));
    }
}
