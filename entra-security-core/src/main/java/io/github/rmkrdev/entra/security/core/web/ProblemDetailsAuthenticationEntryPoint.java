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

    private final BearerTokenAuthenticationEntryPoint bearer = bearerEntryPoint();

    /**
     * Spring Security 7 adds {@code resource_metadata} to {@code WWW-Authenticate} by default. This API does not
     * publish a protected-resource metadata document, and the reactive entry point does not add the parameter, so
     * the resolver returns nothing and both stacks keep {@code Bearer}.
     */
    private static BearerTokenAuthenticationEntryPoint bearerEntryPoint() {
        BearerTokenAuthenticationEntryPoint entryPoint = new BearerTokenAuthenticationEntryPoint();
        entryPoint.setResourceMetadataParameterResolver(request -> null);
        return entryPoint;
    }
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
        String header = response.getHeader("WWW-Authenticate");
        if (header != null && header.contains("resource_metadata=")) {
            response.setHeader("WWW-Authenticate", withoutResourceMetadata(header));
        }
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

    /**
     * Drops {@code resource_metadata}. Spring Security 7 always adds it, including when the resolver returns
     * {@code null} ({@code resource_metadata="null"}).
     */
    static String withoutResourceMetadata(String header) {
        String stripped = header.replaceAll("\\s*resource_metadata=\"[^\"]*\"\\s*,?", "");
        stripped = stripped.replaceAll(",\\s*$", "").replaceAll("\\s{2,}", " ").trim();
        return stripped.isEmpty() ? "Bearer" : stripped;
    }
}
