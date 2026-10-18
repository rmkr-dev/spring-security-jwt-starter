package io.github.rmkrdev.entra.security.core.web;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;

/**
 * The RFC 9457 body used for security errors on both the servlet and the reactive stack.
 */
public final class ProblemDetails {

    private ProblemDetails() {
    }

    /**
     * @param status    the response status
     * @param detail    human-readable explanation
     * @param errorCode OAuth error code such as {@code invalid_token}, or {@code null}
     * @param instance  the request path
     */
    public static Map<String, Object> body(HttpStatus status, String detail, String errorCode, String instance) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "about:blank");
        body.put("title", status.getReasonPhrase());
        body.put("status", status.value());
        body.put("detail", detail);
        body.put("instance", instance);
        if (errorCode != null) {
            body.put("error", errorCode);
        }
        return body;
    }
}
