package io.github.rmkrdev.entra.security.core.web;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.github.rmkrdev.entra.security.core.cae.ClaimsChallengeException;
import io.github.rmkrdev.entra.security.core.cae.ClaimsChallengeResponses;

/** Spring MVC: renders a {@link ClaimsChallengeException}, see {@link ClaimsChallengeResponses}. */
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE - 1000)
public class ClaimsChallengeExceptionHandler {

    @ExceptionHandler(ClaimsChallengeException.class)
    public ResponseEntity<Map<String, Object>> claimsChallenge(ClaimsChallengeException ex,
            HttpServletRequest request) {
        return ClaimsChallengeResponses.response(ex, SecurityContextHolder.getContext().getAuthentication(),
                request.getRequestURI());
    }
}
