package io.github.rmkrdev.entra.security.core.web.server;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;

import io.github.rmkrdev.entra.security.core.jwt.JwtAuthenticationOutcomes;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import reactor.core.publisher.Mono;

/**
 * WebFlux counterpart of {@code ProblemDetailsAuthenticationEntryPoint}: responds 401 with a
 * {@code WWW-Authenticate: Bearer ...} header and a problem-details body.
 */
public final class ServerProblemDetailsAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final BearerTokenServerAuthenticationEntryPoint bearer = new BearerTokenServerAuthenticationEntryPoint();
    private final ServerProblemDetailsWriter writer;
    private final EntraSecurityObservations observations;

    public ServerProblemDetailsAuthenticationEntryPoint(ServerProblemDetailsWriter writer) {
        this(writer, EntraSecurityObservations.NO_OP);
    }

    /**
     * @param observations notified when a protected request has no bearer token. Invalid tokens are
     *                     counted by the decoder instead, so they are not recorded again here.
     */
    public ServerProblemDetailsAuthenticationEntryPoint(ServerProblemDetailsWriter writer,
            EntraSecurityObservations observations) {
        this.writer = writer;
        this.observations = observations == null ? EntraSecurityObservations.NO_OP : observations;
    }

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException authException) {
        return Mono.defer(() -> {
            if (observations != EntraSecurityObservations.NO_OP
                    && !(authException instanceof OAuth2AuthenticationException)) {
                observations.jwtAuthentication(false, JwtAuthenticationOutcomes.MISSING);
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
            String body = detail;
            String errorCode = code;
            return bearer.commence(HeadersOnlyExchange.of(exchange), authException)
                    .then(Mono.defer(() -> writer.write(exchange, HttpStatus.UNAUTHORIZED, body, errorCode)));
        });
    }
}
