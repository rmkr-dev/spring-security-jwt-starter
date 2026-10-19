package io.github.rmkrdev.entra.security.core.web.server;

import java.time.Duration;
import java.util.Optional;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;

import io.github.rmkrdev.entra.security.core.decision.AuthDecision;
import io.github.rmkrdev.entra.security.core.decision.AuthDecisionRecorder;

import reactor.core.publisher.Mono;

/**
 * WebFlux counterpart of {@code ServletAuthTiming}: times the work between the authentication and the end of
 * the authorization web filters, or up to the 401/403 handler.
 */
public final class ReactiveAuthTiming {

    static final String START = ReactiveAuthTiming.class.getName() + ".start";
    static final String DONE = ReactiveAuthTiming.class.getName() + ".done";

    private final AuthDecisionRecorder recorder;

    public ReactiveAuthTiming(AuthDecisionRecorder recorder) {
        this.recorder = recorder;
    }

    /** Goes before the authentication web filter. */
    public WebFilter startFilter() {
        return (exchange, chain) -> {
            exchange.getAttributes().put(START, System.nanoTime());
            return chain.filter(exchange);
        };
    }

    /** Goes after the authorization web filter: reaching it means URL authorization passed. */
    public WebFilter endFilter() {
        return (exchange, chain) -> current().flatMap(found -> {
            Authentication authentication = found.orElse(null);
            boolean anonymous = authentication == null || authentication instanceof AnonymousAuthenticationToken;
            Object start = exchange.getAttribute(START);
            if ((anonymous && !hasToken(exchange)) || !(start instanceof Long startNanos)) {
                exchange.getAttributes().put(DONE, Boolean.TRUE);
                return chain.filter(exchange);
            }
            Duration duration = AuthDecisionRecorder.since(startNanos);
            if (recorder.isServerTiming()) {
                exchange.getResponse().getHeaders().set(AuthDecisionRecorder.SERVER_TIMING,
                        AuthDecisionRecorder.serverTimingValue(duration));
            }
            Object reason = exchange.getAttribute(AuthDecision.REASON_ATTRIBUTE);
            String successReason = reason != null ? reason.toString() : "authorized";
            return chain.filter(exchange)
                    .doOnSuccess(done -> complete(exchange, false, duration, AuthDecision.SUCCESS, successReason,
                            authentication))
                    .doOnError(error -> {
                        if (!AuthDecisionRecorder.isAccessDenied(error)) {
                            complete(exchange, false, duration, AuthDecision.SUCCESS, successReason,
                                    authentication);
                        }
                    });
        });
    }

    /** Records an unauthenticated decision before {@code delegate} writes the 401. */
    public ServerAuthenticationEntryPoint wrap(ServerAuthenticationEntryPoint delegate) {
        return (exchange, exception) -> Mono.defer(() -> {
            completeNow(exchange, AuthDecision.UNAUTHENTICATED, AuthDecisionRecorder.reason(exception), null);
            return delegate.commence(exchange, exception);
        });
    }

    /** Records a forbidden decision before {@code delegate} writes the 403. */
    public ServerAccessDeniedHandler wrap(ServerAccessDeniedHandler delegate) {
        return (exchange, denied) -> current().flatMap(authentication -> {
            completeNow(exchange, AuthDecision.FORBIDDEN, "access_denied", authentication.orElse(null));
            return delegate.handle(exchange, denied);
        });
    }

    private void completeNow(ServerWebExchange exchange, String outcome, String reason,
            Authentication authentication) {
        if (exchange.getAttribute(START) instanceof Long startNanos) {
            complete(exchange, true, AuthDecisionRecorder.since(startNanos), outcome, reason, authentication);
        }
    }

    void complete(ServerWebExchange exchange, boolean header, Duration duration, String outcome, String reason,
            Authentication authentication) {
        if (exchange.getAttribute(DONE) != null) {
            return;
        }
        exchange.getAttributes().put(DONE, Boolean.TRUE);
        ServerHttpRequest request = exchange.getRequest();
        AuthDecision decision = recorder.record(duration, outcome, reason, authentication, hasToken(exchange),
                request.getMethod().name(), request.getPath().value(), request.getHeaders()::getFirst);
        if (header && recorder.isServerTiming() && !exchange.getResponse().isCommitted()) {
            exchange.getResponse().getHeaders().set(AuthDecisionRecorder.SERVER_TIMING,
                    AuthDecisionRecorder.serverTimingValue(decision));
        }
    }

    private static boolean hasToken(ServerWebExchange exchange) {
        return AuthDecisionRecorder.isBearer(exchange.getRequest().getHeaders().getFirst("Authorization"));
    }

    private static Mono<Optional<Authentication>> current() {
        return ReactiveSecurityContextHolder.getContext().mapNotNull(SecurityContext::getAuthentication)
                .map(Optional::of).defaultIfEmpty(Optional.empty());
    }
}
