package io.github.rmkrdev.entra.security.core.web.server;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;

import io.github.rmkrdev.entra.security.core.token.EntraInteractionRequiredException;
import io.github.rmkrdev.entra.security.core.web.InteractionRequiredProblems;

/**
 * WebFlux counterpart of {@code InteractionRequiredExceptionHandler}: an {@link EntraInteractionRequiredException}
 * from an annotated controller (for example from an on-behalf-of {@code WebClient} call) becomes a {@code 403}
 * problem-details response.
 */
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE - 1000)
public class ServerInteractionRequiredExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ServerInteractionRequiredExceptionHandler.class);

    @ExceptionHandler(EntraInteractionRequiredException.class)
    public ResponseEntity<Map<String, Object>> interactionRequired(EntraInteractionRequiredException ex,
            ServerWebExchange exchange) {
        log.info("Responding 403 {}: {}", ex.getProblemErrorCode(), ex.getMessage());
        return InteractionRequiredProblems.response(ex, exchange.getRequest().getPath().value());
    }
}
