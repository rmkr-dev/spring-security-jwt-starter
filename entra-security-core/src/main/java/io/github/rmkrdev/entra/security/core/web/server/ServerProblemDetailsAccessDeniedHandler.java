package io.github.rmkrdev.entra.security.core.web.server;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * WebFlux counterpart of {@code ProblemDetailsAccessDeniedHandler}: responds 403 with a
 * {@code WWW-Authenticate: Bearer error="insufficient_scope"} header and a problem-details body.
 */
public final class ServerProblemDetailsAccessDeniedHandler implements ServerAccessDeniedHandler {

    private final BearerTokenServerAccessDeniedHandler bearer = new BearerTokenServerAccessDeniedHandler();
    private final ServerProblemDetailsWriter writer;

    public ServerProblemDetailsAccessDeniedHandler(ServerProblemDetailsWriter writer) {
        this.writer = writer;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        return bearer.handle(HeadersOnlyExchange.of(exchange), denied)
                .then(Mono.defer(() -> writer.write(exchange, HttpStatus.FORBIDDEN,
                        "The caller does not have a role required to access this resource", "insufficient_scope")));
    }
}
