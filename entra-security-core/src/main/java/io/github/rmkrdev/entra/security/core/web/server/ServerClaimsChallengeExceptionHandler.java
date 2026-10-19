package io.github.rmkrdev.entra.security.core.web.server;

import java.util.Map;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;

import io.github.rmkrdev.entra.security.core.cae.ClaimsChallengeException;
import io.github.rmkrdev.entra.security.core.cae.ClaimsChallengeResponses;

import reactor.core.publisher.Mono;

/** WebFlux: renders a {@link ClaimsChallengeException}, see {@link ClaimsChallengeResponses}. */
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE - 1000)
public class ServerClaimsChallengeExceptionHandler {

    @ExceptionHandler(ClaimsChallengeException.class)
    public Mono<ResponseEntity<Map<String, Object>>> claimsChallenge(ClaimsChallengeException ex,
            ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().value();
        return ReactiveSecurityContextHolder.getContext().mapNotNull(SecurityContext::getAuthentication)
                .map(authentication -> ClaimsChallengeResponses.response(ex, authentication, path))
                .defaultIfEmpty(ClaimsChallengeResponses.response(ex, null, path));
    }
}
