package io.github.rmkrdev.entra.security.core.decision;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Writes one line per {@link AuthDecision} to the SLF4J logger {@value #LOGGER_NAME} at INFO, so it ends up in
 * the normal application log or stdout and whatever ships that (Datadog, Splunk, Loki) picks it up unchanged.
 * <p>
 * The line never contains a token, a name, a user principal name or an e-mail address: the caller is identified
 * by {@code tid} and {@code oid} (users) or {@code appid} (services) only. The path is logged without its query
 * string.
 */
public final class AuditLogger implements AuthDecisionListener {

    /** The logger name, so the audit lines can be routed or silenced on their own. */
    public static final String LOGGER_NAME = "entra.security.audit";

    /** Output format. */
    public enum Format {
        /** A single JSON object per line. */
        JSON,
        /** A single {@code key=value} line. */
        FLAT
    }

    private final Logger log;
    private final Format format;

    public AuditLogger(Format format) {
        this(format, LoggerFactory.getLogger(LOGGER_NAME));
    }

    AuditLogger(Format format, Logger log) {
        this.format = format == null ? Format.JSON : format;
        this.log = log;
    }

    @Override
    public void onDecision(AuthDecision decision) {
        if (log.isInfoEnabled()) {
            log.info(format(decision));
        }
    }

    /** The audit line for {@code decision}. */
    public String format(AuthDecision decision) {
        Map<String, Object> fields = fields(decision);
        return format == Format.FLAT ? flat(fields) : json(fields);
    }

    static Map<String, Object> fields(AuthDecision decision) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("ts", decision.timestamp().toString());
        fields.put("traceId", decision.correlationId());
        fields.put("outcome", decision.outcome());
        fields.put("reason", decision.reason());
        fields.put("tokenType", decision.tokenType());
        fields.put("validationMode", decision.validationMode());
        fields.put("tid", decision.tenantId());
        fields.put("service".equals(decision.tokenType()) ? "appid" : "oid", decision.callerId());
        fields.put("roles", decision.roles());
        fields.put("method", decision.method());
        fields.put("path", decision.path());
        fields.put("authMs", String.format(Locale.ROOT, "%.3f", decision.durationMillis()));
        return fields;
    }

    private static String flat(Map<String, Object> fields) {
        StringBuilder line = new StringBuilder();
        fields.forEach((key, value) -> {
            if (value == null) {
                return;
            }
            String text = value instanceof List<?> list ? String.join(",", list.stream().map(String::valueOf)
                    .toList()) : value.toString();
            if (line.length() > 0) {
                line.append(' ');
            }
            line.append(key).append('=');
            if (text.isEmpty() || text.chars().anyMatch(c -> c == ' ' || c == '"' || c == '=' || c < 0x20)) {
                line.append('"').append(text.replace("\\", "\\\\").replace("\"", "\\\"")
                        .replaceAll("[\\x00-\\x1f]", "_")).append('"');
            }
            else {
                line.append(text);
            }
        });
        return line.toString();
    }

    private static String json(Map<String, Object> fields) {
        StringBuilder json = new StringBuilder("{");
        fields.forEach((key, value) -> {
            if (value == null) {
                return;
            }
            if (json.length() > 1) {
                json.append(',');
            }
            json.append('"').append(key).append("\":");
            if (value instanceof List<?> list) {
                json.append('[');
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) {
                        json.append(',');
                    }
                    quote(json, String.valueOf(list.get(i)));
                }
                json.append(']');
            }
            else if ("authMs".equals(key)) {
                json.append(value);
            }
            else {
                quote(json, value.toString());
            }
        });
        return json.append('}').toString();
    }

    private static void quote(StringBuilder json, String value) {
        json.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> json.append("\\\"");
                case '\\' -> json.append("\\\\");
                case '\n' -> json.append("\\n");
                case '\r' -> json.append("\\r");
                case '\t' -> json.append("\\t");
                default -> {
                    if (c < 0x20) {
                        json.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        json.append(c);
                    }
                }
            }
        }
        json.append('"');
    }
}
