package io.github.rmkrdev.entra.security.core.web.server;

import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Lets Spring Security's bearer handlers set the status and {@code WWW-Authenticate} header without
 * completing the response, so the problem-details body can be written afterwards.
 */
final class HeadersOnlyExchange {

    private HeadersOnlyExchange() {
    }

    static ServerWebExchange of(ServerWebExchange exchange) {
        ServerHttpResponseDecorator response = new ServerHttpResponseDecorator(exchange.getResponse()) {
            @Override
            public Mono<Void> setComplete() {
                return Mono.empty();
            }
        };
        return exchange.mutate().response(response).build();
    }
}
