package io.github.rmkrdev.entra.security.core.decision;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import jakarta.servlet.ServletException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import io.github.rmkrdev.entra.security.core.web.ServletAuthTiming;

class AuthDecisionRecorderTest {

    private final List<AuthDecision> decisions = new ArrayList<>();

    @AfterEach
    void clear() {
        MDC.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void correlationIdComesFromMdcTraceparentHeaderOrIsGenerated() {
        Map<String, String> headers = new java.util.HashMap<>();
        assertThat(AuthDecisionRecorder.correlationId(headers::get)).hasSize(36);
        headers.put("X-Request-ID", "req 1");
        assertThat(AuthDecisionRecorder.correlationId(headers::get)).isEqualTo("req_1");
        headers.put("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        assertThat(AuthDecisionRecorder.correlationId(headers::get)).isEqualTo("4bf92f3577b34da6a3ce929d0e0e4736");
        headers.put("traceparent", "junk");
        assertThat(AuthDecisionRecorder.correlationId(headers::get)).isEqualTo("req_1");
        MDC.put("traceId", "abc123");
        assertThat(AuthDecisionRecorder.correlationId(headers::get)).isEqualTo("abc123");
    }

    @Test
    void reasonsAndHelpers() {
        assertThat(AuthDecisionRecorder.reason(new BadCredentialsException("x"))).isEqualTo("missing");
        assertThat(AuthDecisionRecorder.reason(new OAuth2AuthenticationException(new OAuth2Error("invalid_token",
                "Jwt expired at 2020", null)))).isEqualTo("expired");
        assertThat(AuthDecisionRecorder.isBearer("bearer abc")).isTrue();
        assertThat(AuthDecisionRecorder.isBearer("Basic abc")).isFalse();
        assertThat(AuthDecisionRecorder.isBearer(null)).isFalse();
        assertThat(AuthDecisionRecorder.isAccessDenied(new ServletException(new AccessDeniedException("no"))))
                .isTrue();
        assertThat(AuthDecisionRecorder.isAccessDenied(new IllegalStateException())).isFalse();
        assertThat(AuthDecisionRecorder.serverTimingValue(Duration.ofNanos(1_500_000))).isEqualTo("auth;dur=1.500");
    }

    @Test
    void failingListenersDoNotBreakTheRequestAndOtherAuthenticationsAreUnknown() {
        AuthDecisionRecorder recorder = new AuthDecisionRecorder("HYBRID", List.of(decision -> {
            throw new IllegalStateException("boom");
        }, decisions::add), true, Clock.systemUTC());
        AuthDecision decision = recorder.record(Duration.ofMillis(2), AuthDecision.SUCCESS, "authorized",
                new TestingAuthenticationToken("u", "p", "ROLE_X"), true, "GET", "/x", name -> null);
        assertThat(decisions).containsExactly(decision);
        assertThat(decision.validationMode()).isEqualTo("hybrid");
        assertThat(decision.tokenType()).isEqualTo("unknown");
        assertThat(decision.roles()).containsExactly("ROLE_X");
        assertThat(decision.durationMillis()).isEqualTo(2.0);
        assertThat(new AuthDecisionRecorder(null, List.of(), false, Clock.systemUTC()).record(Duration.ZERO,
                AuthDecision.UNAUTHENTICATED, "missing", null, false, "GET", "/", name -> null).tokenType())
                .isEqualTo("none");
    }

    @Test
    void servletTimingWithoutHeaderAndOnErrors() throws Exception {
        ServletAuthTiming timing = new ServletAuthTiming(new AuthDecisionRecorder("jwks", List.of(decisions::add),
                false, Clock.systemUTC()));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.addHeader("Authorization", "Bearer x");
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("u", "p", "ROLE_X"));
        timing.startFilter().doFilter(request, response, new MockFilterChain(new jakarta.servlet.http.HttpServlet() {
        }, timing.endFilter()));
        assertThat(response.getHeader("Server-Timing")).isNull();
        assertThat(decisions).singleElement().extracting(AuthDecision::outcome).isEqualTo("success");

        decisions.clear();
        MockHttpServletRequest failing = new MockHttpServletRequest("GET", "/orders");
        failing.addHeader("Authorization", "Bearer x");
        try {
            timing.startFilter().doFilter(failing, new MockHttpServletResponse(), (req, res) -> {
                throw new IllegalStateException("boom");
            });
        }
        catch (IllegalStateException expected) {
            // recorded as an error
        }
        assertThat(decisions).singleElement().extracting(AuthDecision::outcome).isEqualTo("error");
    }
}
