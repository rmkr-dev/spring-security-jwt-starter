package io.github.rmkrdev.entra.security.core.web;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.github.rmkrdev.entra.security.core.token.EntraInteractionRequiredException;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Spring MVC: turns an {@link EntraInteractionRequiredException} thrown while handling a request (for example
 * by an on-behalf-of {@code RestClient} call) into a {@code 403} problem-details response, see
 * {@link InteractionRequiredProblems}.
 */
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE - 1000)
public class InteractionRequiredExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(InteractionRequiredExceptionHandler.class);

    @ExceptionHandler(EntraInteractionRequiredException.class)
    public ResponseEntity<Map<String, Object>> interactionRequired(EntraInteractionRequiredException ex,
            HttpServletRequest request) {
        log.info("Responding 403 {}: {}", ex.getProblemErrorCode(), ex.getMessage());
        return InteractionRequiredProblems.response(ex, request.getRequestURI());
    }
}
