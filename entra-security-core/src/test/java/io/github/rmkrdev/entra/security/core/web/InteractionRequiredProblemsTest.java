package io.github.rmkrdev.entra.security.core.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import io.github.rmkrdev.entra.security.core.token.EntraInteractionRequiredException;

class InteractionRequiredProblemsTest {

    @Test
    void consentRequiredIsA403ProblemNamingTheScope() {
        EntraInteractionRequiredException ex = new EntraInteractionRequiredException("AADSTS65001 ...",
                "invalid_grant", "consent_required", "api://orders/Orders.Read", null, List.of(65001));

        ResponseEntity<Map<String, Object>> response = InteractionRequiredProblems.response(ex, "/api/orders");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .startsWith("Bearer error=\"consent_required\"").doesNotContain("claims=");
        assertThat(response.getBody()).containsEntry("status", 403).containsEntry("error", "consent_required")
                .containsEntry("instance", "/api/orders").containsEntry("scope", "api://orders/Orders.Read")
                .doesNotContainKey("claims");
        assertThat(response.getBody().get("detail").toString()).contains("consent").doesNotContain("AADSTS");
    }

    @Test
    void claimsChallengeIsPassedOnInBodyAndHeader() {
        String claims = "{\"access_token\":{\"capolids\":{\"essential\":true,\"values\":[\"p1\"]}}}";
        EntraInteractionRequiredException ex = new EntraInteractionRequiredException("AADSTS50076 ...",
                "interaction_required", "basic_action", "api://orders/.default", claims, List.of(50076));

        ResponseEntity<Map<String, Object>> response = InteractionRequiredProblems.response(ex, "/x");

        String encoded = Base64.getEncoder().encodeToString(claims.getBytes(StandardCharsets.UTF_8));
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .startsWith("Bearer error=\"interaction_required\"").endsWith("claims=\"" + encoded + "\"");
        assertThat(response.getBody()).containsEntry("error", "interaction_required").containsEntry("claims", claims);
    }
}
