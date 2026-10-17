package io.github.rmkrdev.entra.security.core.web;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Responds 403 with a {@code WWW-Authenticate: Bearer error="insufficient_scope"} header and a
 * problem-details body.
 */
public final class ProblemDetailsAccessDeniedHandler implements AccessDeniedHandler {

    private final BearerTokenAccessDeniedHandler bearer = new BearerTokenAccessDeniedHandler();
    private final ProblemDetailsWriter writer;

    public ProblemDetailsAccessDeniedHandler(ProblemDetailsWriter writer) {
        this.writer = writer;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException, ServletException {
        bearer.handle(request, response, accessDeniedException);
        writer.write(request, response, HttpStatus.FORBIDDEN,
                "The caller does not have a role required to access this resource", "insufficient_scope");
    }
}
