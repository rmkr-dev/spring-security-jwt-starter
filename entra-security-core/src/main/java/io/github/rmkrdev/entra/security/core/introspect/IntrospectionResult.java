package io.github.rmkrdev.entra.security.core.introspect;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The answer of a remote token check.
 *
 * @param active whether the authority considers the token active
 * @param claims the claims it returned (empty for an inactive token)
 */
public record IntrospectionResult(boolean active, Map<String, Object> claims) {

    private static final IntrospectionResult INACTIVE = new IntrospectionResult(false, Map.of());

    public IntrospectionResult {
        claims = claims == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    /** An active token with the given claims. */
    public static IntrospectionResult active(Map<String, Object> claims) {
        return new IntrospectionResult(true, claims);
    }

    /** An inactive (unknown, expired or revoked) token. */
    public static IntrospectionResult inactive() {
        return INACTIVE;
    }
}
