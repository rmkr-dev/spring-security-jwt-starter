package io.github.rmkrdev.entra.security.core.decision;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

class AuditLoggerTest {

    private static final AuthDecision USER = new AuthDecision(Instant.parse("2026-10-19T06:00:00Z"), "trace-1",
            "success", "authorized", "user", "jwks", "tid-1", "oid-1", List.of("ROLE_A", "ROLE_B"), "GET",
            "/orders", Duration.ofNanos(412_000));

    @Test
    void jsonIsOneParseableObjectWithAllFields() throws Exception {
        String line = new AuditLogger(AuditLogger.Format.JSON).format(USER);
        assertThat(line).doesNotContain("\n");
        JsonNode json = new ObjectMapper().readTree(line);
        assertThat(json.get("ts").asText()).isEqualTo("2026-10-19T06:00:00Z");
        assertThat(json.get("traceId").asText()).isEqualTo("trace-1");
        assertThat(json.get("outcome").asText()).isEqualTo("success");
        assertThat(json.get("reason").asText()).isEqualTo("authorized");
        assertThat(json.get("tokenType").asText()).isEqualTo("user");
        assertThat(json.get("tid").asText()).isEqualTo("tid-1");
        assertThat(json.get("oid").asText()).isEqualTo("oid-1");
        assertThat(json.get("roles")).hasSize(2);
        assertThat(json.get("path").asText()).isEqualTo("/orders");
        assertThat(json.get("method").asText()).isEqualTo("GET");
        assertThat(json.get("authMs").asDouble()).isEqualTo(0.412);
    }

    @Test
    void flatIsASingleKeyValueLineAndServicesUseAppid() {
        AuthDecision service = new AuthDecision(USER.timestamp(), "t", "forbidden", "access_denied", "service",
                "jwks", "tid-1", "app-1", List.of(), "POST", "/a b\"\n", Duration.ofMillis(1));
        String line = new AuditLogger(AuditLogger.Format.FLAT).format(service);
        assertThat(line).startsWith("ts=2026-10-19T06:00:00Z traceId=t outcome=forbidden reason=access_denied "
                + "tokenType=service").contains(" appid=app-1 ").contains("roles=\"\"")
                .contains("path=\"/a b\\\"_\"").endsWith("authMs=1.000").doesNotContain("oid=").doesNotContain("\n");
    }

    @Test
    void jsonEscapesAndSkipsNulls() throws Exception {
        AuthDecision missing = new AuthDecision(USER.timestamp(), "t", "unauthenticated", "missing", "none", "jwks",
                null, null, null, "GET", "/x\"\\\t\r\n\u0001", Duration.ZERO);
        AuditLogger logger = new AuditLogger(null, LoggerFactory.getLogger("test"));
        String line = logger.format(missing);
        assertThat(line).doesNotContain("\"tid\"").doesNotContain("\"oid\"");
        assertThat(new ObjectMapper().readTree(line).get("path").asText()).isEqualTo("/x\"\\\t\r\n\u0001");
        logger.onDecision(missing);
    }
}
