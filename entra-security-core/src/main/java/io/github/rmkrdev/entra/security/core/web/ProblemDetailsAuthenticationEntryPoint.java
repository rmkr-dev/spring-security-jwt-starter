package io.github.rmkrdev.entra.security.core.web;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Responds 401 with a {@code WWW-Authenticate: Bearer ...} header and a problem-details body.
 */
public final class ProblemDetailsAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final BearerTokenAuthenticationEntryPoint bearer = new BearerTokenAuthenticationEntryPoint();
    private final ProblemDetailsWriter writer;

    public ProblemDetailsAuthenticationEntryPoint(ProblemDetailsWriter writer) {
        this.writer = writer;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        bearer.commence(request, response, authException);
        String detail = "A valid bearer token is required to access this resource";
        String code = "unauthorized";
        if (authException instanceof OAuth2AuthenticationException oauth) {
            OAuth2Error error = oauth.getError();
            code = error.getErrorCode();
            if (error.getDescription() != null) {
                detail = error.getDescription();
            }
        }
        writer.write(request, response, HttpStatus.UNAUTHORIZED, detail, code);
    }
}
