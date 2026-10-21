package io.github.rmkrdev.entra.security.core.web;

import java.io.IOException;
import java.time.Duration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.rmkrdev.entra.security.core.decision.AuthDecision;
import io.github.rmkrdev.entra.security.core.decision.AuthDecisionRecorder;

/**
 * Times the authentication work of a servlet request: from just before the bearer token filter to the end of
 * the authorization filter, or to the 401/403 handler. Validation, role mapping, the Graph overage lookup and
 * URL authorization fall inside that window. A method-security denial ({@code @Secured}) is recorded as
 * forbidden, timed up to the access-denied handler.
 * <p>
 * Requests without a bearer token that are allowed anyway (public paths) are not recorded.
 */
public final class ServletAuthTiming {

    static final String START = ServletAuthTiming.class.getName() + ".start";
    static final String DONE = ServletAuthTiming.class.getName() + ".done";

    private final AuthDecisionRecorder recorder;

    public ServletAuthTiming(AuthDecisionRecorder recorder) {
        this.recorder = recorder;
    }

    /** Goes before the bearer token filter. */
    public OncePerRequestFilter startFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                    FilterChain chain) throws ServletException, IOException {
                long start = System.nanoTime();
                request.setAttribute(START, start);
                boolean failed = true;
                try {
                    chain.doFilter(request, response);
                    failed = false;
                }
                finally {
                    if (failed && hasToken(request)) {
                        complete(request, response, AuthDecisionRecorder.since(start), AuthDecision.ERROR,
                                "exception", current());
                    }
                }
            }
        };
    }

    /** Goes after the authorization filter: reaching it means URL authorization passed. */
    public OncePerRequestFilter endFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                    FilterChain chain) throws ServletException, IOException {
                Authentication authentication = current();
                boolean anonymous = authentication == null || authentication instanceof AnonymousAuthenticationToken;
                Object start = request.getAttribute(START);
                if ((anonymous && !hasToken(request)) || !(start instanceof Long startNanos)) {
                    request.setAttribute(DONE, Boolean.TRUE);
                    chain.doFilter(request, response);
                    return;
                }
                Duration duration = AuthDecisionRecorder.since(startNanos);
                if (recorder.isServerTiming()) {
                    response.setHeader(AuthDecisionRecorder.SERVER_TIMING,
                            AuthDecisionRecorder.serverTimingValue(duration));
                }
                Throwable failure = null;
                try {
                    chain.doFilter(request, response);
                }
                catch (IOException | ServletException | RuntimeException | Error ex) {
                    failure = ex;
                    throw ex;
                }
                finally {
                    if (failure == null || !AuthDecisionRecorder.isAccessDenied(failure)) {
                        Object reason = request.getAttribute(AuthDecision.REASON_ATTRIBUTE);
                        complete(request, null, duration, AuthDecision.SUCCESS,
                                reason != null ? reason.toString() : "authorized", authentication);
                    }
                }
            }
        };
    }

    /** Records an unauthenticated decision before {@code delegate} writes the 401. */
    @SuppressWarnings("overloads")
    public AuthenticationEntryPoint wrap(AuthenticationEntryPoint delegate) {
        return (request, response, exception) -> {
            completeNow(request, response, AuthDecision.UNAUTHENTICATED, AuthDecisionRecorder.reason(exception),
                    null);
            delegate.commence(request, response, exception);
        };
    }

    /** Records a forbidden decision before {@code delegate} writes the 403. */
    @SuppressWarnings("overloads")
    public AccessDeniedHandler wrap(AccessDeniedHandler delegate) {
        return (request, response, exception) -> {
            completeNow(request, response, AuthDecision.FORBIDDEN, "access_denied", current());
            delegate.handle(request, response, exception);
        };
    }

    private void completeNow(HttpServletRequest request, HttpServletResponse response, String outcome,
            String reason, Authentication authentication) {
        if (request.getAttribute(START) instanceof Long startNanos) {
            complete(request, response, AuthDecisionRecorder.since(startNanos), outcome, reason, authentication);
        }
    }

    /**
     * @param response where the {@code Server-Timing} header goes, or {@code null} when it was already set
     */
    void complete(HttpServletRequest request, HttpServletResponse response, Duration duration, String outcome,
            String reason, Authentication authentication) {
        if (request.getAttribute(DONE) != null) {
            return;
        }
        request.setAttribute(DONE, Boolean.TRUE);
        AuthDecision decision = recorder.record(duration, outcome, reason, authentication, hasToken(request),
                request.getMethod(), request.getRequestURI(), request::getHeader);
        if (response != null && recorder.isServerTiming() && !response.isCommitted()) {
            response.setHeader(AuthDecisionRecorder.SERVER_TIMING, AuthDecisionRecorder.serverTimingValue(decision));
        }
    }

    private static boolean hasToken(HttpServletRequest request) {
        return AuthDecisionRecorder.isBearer(request.getHeader("Authorization"));
    }

    private static Authentication current() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
