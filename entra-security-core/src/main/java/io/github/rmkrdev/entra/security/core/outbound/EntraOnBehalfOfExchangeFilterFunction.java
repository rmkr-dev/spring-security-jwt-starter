package io.github.rmkrdev.entra.security.core.outbound;

import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;

import io.github.rmkrdev.entra.security.core.token.EntraOnBehalfOfTokenProvider;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Adds a downstream token acquired on behalf of the current user to outgoing {@code WebClient} requests.
 * <p>
 * The user's token comes from the Reactor context ({@code ReactiveSecurityContextHolder}) on WebFlux, so the
 * call must be part of the request's reactive chain. In a servlet application that blocks on a
 * {@code WebClient}, the thread-local {@code SecurityContextHolder} of the subscribing thread is used.
 * Token acquisition is blocking I/O and runs on the bounded-elastic scheduler; cached tokens return
 * immediately.
 * <p>
 * Errors with {@link io.github.rmkrdev.entra.security.core.token.EntraInteractionRequiredException} when the
 * user has to consent or sign in again.
 */
public final class EntraOnBehalfOfExchangeFilterFunction implements ExchangeFilterFunction {

    private final EntraOnBehalfOfTokenProvider tokenProvider;
    private final String scope;

    public EntraOnBehalfOfExchangeFilterFunction(EntraOnBehalfOfTokenProvider tokenProvider, String scope) {
        this.tokenProvider = tokenProvider;
        this.scope = scope;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        Jwt threadToken = EntraUserTokens.current().orElse(null);
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .flatMap(authentication -> Mono.justOrEmpty(EntraUserTokens.from(authentication)))
                .switchIfEmpty(Mono.justOrEmpty(threadToken))
                .switchIfEmpty(Mono.error(EntraUserTokens::missing))
                .flatMap(jwt -> Mono.fromCallable(() -> tokenProvider.getToken(jwt, scope))
                        .subscribeOn(Schedulers.boundedElastic()))
                .flatMap(token -> next.exchange(ClientRequest.from(request)
                        .headers(headers -> headers.setBearerAuth(token.value()))
                        .build()));
    }
}
