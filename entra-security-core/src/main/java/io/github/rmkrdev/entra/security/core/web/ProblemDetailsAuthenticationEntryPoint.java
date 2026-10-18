package io.github.rmkrdev.entra.security.core.web;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;

import io.github.rmkrdev.entra.security.core.jwt.JwtAuthenticationOutcomes;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Responds 401 with a {@code WWW-Authenticate: Bearer ...} header and a problem-details body.
 */
public final class ProblemDetailsAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final BearerTokenAuthenticationEntryPoint bearer = new BearerTokenAuthenticationEntryPoint();
    private final ProblemDetailsWriter writer;
    private final EntraSecurityObservations observations;

    public ProblemDetailsAuthenticationEntryPoint(ProblemDetailsWriter writer) {
        this(writer, EntraSecurityObservations.NO_OP);
    }

    /**
     * @param observations notified when a protected request has no bearer token. Invalid tokens are
     *                     counted by the decoder instead, so they are not recorded again here.
     */
    public ProblemDetailsAuthenticationEntryPoint(ProblemDetailsWriter writer,
            EntraSecurityObservations observations) {
        this.writer = writer;
        this.observations = observations == null ? EntraSecurityObservations.NO_OP : observations;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        if (observations != EntraSecurityObservations.NO_OP
                && !(authException instanceof OAuth2AuthenticationException)) {
            observations.jwtAuthentication(false, JwtAuthenticationOutcomes.MISSING);
        }
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
