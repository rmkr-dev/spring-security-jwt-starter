package io.github.rmkrdev.entra.security.core.decision;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * One authentication and authorization decision for an API call. Holds no token and no personal data: the
 * caller is identified only by the tenant id and the object id (users) or application id (services).
 *
 * @param timestamp      when the decision was made
 * @param correlationId  the request's trace or correlation id
 * @param outcome        {@link #SUCCESS}, {@link #UNAUTHENTICATED}, {@link #FORBIDDEN} or {@link #ERROR}
 * @param reason         a bounded label, for example {@code authorized}, {@code expired} or {@code access_denied}
 * @param tokenType      {@code user}, {@code service}, {@code unknown} or {@code none}
 * @param validationMode {@code jwks}, {@code introspection} or {@code hybrid}
 * @param tenantId       the {@code tid} claim, or {@code null}
 * @param callerId       the {@code oid} for users, the client application id for services, or {@code null}
 * @param roles          the mapped role authorities
 * @param method         the HTTP method
 * @param path           the request path, without the query string
 * @param duration       the time spent on validation, role mapping, Graph and authorization
 */
public record AuthDecision(Instant timestamp, String correlationId, String outcome, String reason, String tokenType,
        String validationMode, String tenantId, String callerId, List<String> roles, String method, String path,
        Duration duration) {

    public static final String SUCCESS = "success";
    public static final String UNAUTHENTICATED = "unauthenticated";
    public static final String FORBIDDEN = "forbidden";
    public static final String ERROR = "error";

    /**
     * Request (or exchange) attribute holding an override for the success reason, for example
     * {@code role_pattern} when access was granted by {@code allow-role-patterns}.
     */
    public static final String REASON_ATTRIBUTE = AuthDecision.class.getName() + ".reason";

    public AuthDecision {
        roles = roles == null ? List.of() : List.copyOf(roles);
    }

    /** The duration in milliseconds with microsecond precision. */
    public double durationMillis() {
        return duration.toNanos() / 1_000_000.0;
    }
}
