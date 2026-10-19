package io.github.rmkrdev.entra.security.core.outbound;

import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;

import reactor.core.publisher.Mono;

/**
 * The {@code WebClient} counterpart of {@link EntraRoutingInterceptor}: picks the token for each request
 * from the configured routes. Requests that already carry an {@code Authorization} header, go to a skipped
 * host or match no route are sent unchanged.
 */
public final class EntraRoutingExchangeFilterFunction implements ExchangeFilterFunction {

    private final OutboundRouter<ExchangeFilterFunction> router;

    public EntraRoutingExchangeFilterFunction(OutboundRouter<ExchangeFilterFunction> router) {
        this.router = router;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        if (request.headers().containsKey(HttpHeaders.AUTHORIZATION)) {
            return next.exchange(request);
        }
        Optional<OutboundRouter.Route<ExchangeFilterFunction>> route = router.route(request.url());
        return route.isPresent() ? route.get().value().filter(request, next) : next.exchange(request);
    }
}
