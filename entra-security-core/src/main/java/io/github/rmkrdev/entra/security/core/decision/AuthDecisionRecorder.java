package io.github.rmkrdev.entra.security.core.decision;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import io.github.rmkrdev.entra.security.core.jwt.JwtAuthenticationOutcomes;
import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

/**
 * Turns the end of the authentication work for a request into an {@link AuthDecision}, hands it to the listeners
 * (metrics, audit) and formats the {@code Server-Timing} value. Shared by the servlet and reactive stacks.
 */
public final class AuthDecisionRecorder {

    /** Response header carrying the authentication time. */
    public static final String SERVER_TIMING = "Server-Timing";

    private static final Logger log = LoggerFactory.getLogger(AuthDecisionRecorder.class);
    private static final List<String> MDC_KEYS = List.of("traceId", "trace_id", "correlationId", "correlation_id",
            "requestId");
    private static final List<String> HEADERS = List.of("X-Correlation-ID", "X-Request-ID");

    private final String validationMode;
    private final List<AuthDecisionListener> listeners;
    private final boolean serverTiming;
    private final Clock clock;

    /**
     * @param validationMode {@code jwks}, {@code introspection} or {@code hybrid}
     * @param listeners      notified of each decision
     * @param serverTiming   whether {@link #serverTimingValue} should be sent
     */
    public AuthDecisionRecorder(String validationMode, List<AuthDecisionListener> listeners, boolean serverTiming,
            Clock clock) {
        this.validationMode = validationMode == null ? "jwks" : validationMode.toLowerCase(Locale.ROOT);
        this.listeners = List.copyOf(listeners);
        this.serverTiming = serverTiming;
        this.clock = clock;
    }

    public boolean isServerTiming() {
        return serverTiming;
    }

    /**
     * Builds the decision and notifies the listeners.
     *
     * @param duration       the authentication work, see {@link #since(long)}
     * @param outcome        one of the {@link AuthDecision} outcomes
     * @param reason         bounded reason label
     * @param authentication the authenticated caller, or {@code null}
     * @param tokenPresent   whether the request carried a bearer token
     * @param headers        request header lookup
     */
    public AuthDecision record(Duration duration, String outcome, String reason, Authentication authentication,
            boolean tokenPresent, String method, String path, Function<String, String> headers) {
        String tokenType = tokenPresent ? "unknown" : "none";
        String tenantId = null;
        String callerId = null;
        List<String> roles = List.of();
        if (authentication instanceof EntraAuthenticationToken entra) {
            EntraPrincipal principal = entra.getEntraPrincipal();
            tokenType = principal.type() == PrincipalType.SERVICE ? "service" : "user";
            tenantId = principal.tenantId();
            callerId = principal.type() == PrincipalType.SERVICE ? principal.appId() : principal.objectId();
            roles = List.copyOf(principal.roles());
        }
        else if (authentication != null && !(authentication instanceof AnonymousAuthenticationToken)) {
            tokenType = "unknown";
            roles = authentication.getAuthorities().stream().map(Object::toString).toList();
        }
        AuthDecision decision = new AuthDecision(clock.instant(), correlationId(headers), outcome, reason, tokenType,
                validationMode, tenantId, callerId, roles, method, path, duration);
        for (AuthDecisionListener listener : listeners) {
            try {
                listener.onDecision(decision);
            }
            catch (RuntimeException ex) {
                log.warn("Auth decision listener {} failed: {}", listener.getClass().getName(), ex.getMessage());
            }
        }
        return decision;
    }

    /** The time elapsed since {@code startNanos}, a {@link System#nanoTime()} reading. */
    public static Duration since(long startNanos) {
        return Duration.ofNanos(Math.max(0, System.nanoTime() - startNanos));
    }

    /** {@code auth;dur=1.234}. */
    public static String serverTimingValue(Duration duration) {
        return String.format(Locale.ROOT, "auth;dur=%.3f", duration.toNanos() / 1_000_000.0);
    }

    /** {@code auth;dur=1.234}. */
    public static String serverTimingValue(AuthDecision decision) {
        return serverTimingValue(decision.duration());
    }

    /** A bounded reason for a failed authentication. */
    public static String reason(AuthenticationException exception) {
        if (exception instanceof OAuth2AuthenticationException) {
            return JwtAuthenticationOutcomes.reason(exception);
        }
        return JwtAuthenticationOutcomes.MISSING;
    }

    /** Whether {@code error} or one of its causes is an access-denied exception. */
    public static boolean isAccessDenied(Throwable error) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            if (current instanceof org.springframework.security.access.AccessDeniedException) {
                return true;
            }
            if (current.getCause() == current) {
                break;
            }
        }
        return false;
    }

    /** Whether an {@code Authorization} header value carries a bearer token. */
    public static boolean isBearer(String authorization) {
        return authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7);
    }

    /**
     * The request's correlation id: from the logging MDC, the W3C {@code traceparent} trace id, an
     * {@code X-Correlation-ID} or {@code X-Request-ID} header, or a new random id.
     */
    static String correlationId(Function<String, String> headers) {
        for (String key : MDC_KEYS) {
            String value = MDC.get(key);
            if (value != null && !value.isBlank()) {
                return sanitize(value);
            }
        }
        String traceparent = headers.apply("traceparent");
        if (traceparent != null) {
            String[] parts = traceparent.trim().split("-");
            if (parts.length >= 4 && parts[1].matches("[0-9a-f]{32}")) {
                return parts[1];
            }
        }
        for (String header : HEADERS) {
            String value = headers.apply(header);
            if (value != null && !value.isBlank()) {
                return sanitize(value);
            }
        }
        return UUID.randomUUID().toString();
    }

    private static String sanitize(String value) {
        String trimmed = value.length() > 64 ? value.substring(0, 64) : value;
        return trimmed.replaceAll("[^A-Za-z0-9._:-]", "_");
    }
}
