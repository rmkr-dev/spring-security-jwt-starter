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
    private final boolean cae;

    public EntraBearerExchangeFilterFunction(EntraTokenProvider tokenProvider, String scope) {
        this(tokenProvider, scope, false);
    }

    /**
     * @param cae when {@code true}, a {@code 401} with an {@code insufficient_claims} challenge is answered once with
     *            a fresh token for the challenge claims
     */
    public EntraBearerExchangeFilterFunction(EntraTokenProvider tokenProvider, String scope, boolean cae) {
        this.tokenProvider = tokenProvider;
        this.scope = scope;
        this.cae = cae;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        return Mono.fromCallable(() -> tokenProvider.getToken(scope))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(token -> next.exchange(OutboundClaimsChallenge.withToken(request, token)))
                .flatMap(response -> cae ? OutboundClaimsChallenge.retry(request, next, response,
                        claims -> tokenProvider.getToken(scope, claims)) : Mono.just(response));
    }
}
