package io.github.rmkrdev.entra.security.core.outbound;

import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;

import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Adds an app-only Entra bearer token to outgoing {@code WebClient} requests. Token acquisition is
 * blocking I/O, so it runs on the bounded-elastic scheduler (cached tokens return immediately).
 */
public final class EntraBearerExchangeFilterFunction implements ExchangeFilterFunction {

    private final EntraTokenProvider tokenProvider;
    private final String scope;

    public EntraBearerExchangeFilterFunction(EntraTokenProvider tokenProvider, String scope) {
        this.tokenProvider = tokenProvider;
        this.scope = scope;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        return Mono.fromCallable(() -> tokenProvider.getToken(scope))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(token -> next.exchange(ClientRequest.from(request)
                        .headers(headers -> headers.setBearerAuth(token.value()))
                        .build()));
    }
}
