package io.github.rmkrdev.entra.security.core.web;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

class ProblemDetailsTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final ProblemDetailsWriter writer = new ProblemDetailsWriter(mapper);

    @Test
    void unauthorizedInvalidToken() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        new ProblemDetailsAuthenticationEntryPoint(writer).commence(new MockHttpServletRequest("GET", "/api/x"),
                response, new InvalidBearerTokenException("Jwt expired"));
        JsonNode body = mapper.readTree(response.getContentAsString());
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(response.getHeader("WWW-Authenticate")).startsWith("Bearer").contains("invalid_token");
        assertThat(body.get("status").asInt()).isEqualTo(401);
        assertThat(body.get("detail").asString()).isEqualTo("Jwt expired");
        assertThat(body.get("instance").asString()).isEqualTo("/api/x");
        assertThat(body.get("error").asString()).isEqualTo("invalid_token");
    }

    @Test
    void unauthorizedMissingToken() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        new ProblemDetailsAuthenticationEntryPoint(writer).commence(new MockHttpServletRequest("GET", "/api/x"),
                response, new InsufficientAuthenticationException("Full authentication is required"));
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
        assertThat(mapper.readTree(response.getContentAsString()).get("title").asString()).isEqualTo("Unauthorized");
    }

    @Test
    void forbidden() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        new ProblemDetailsAccessDeniedHandler(writer).handle(new MockHttpServletRequest("GET", "/api/y"), response,
                new AccessDeniedException("Access Denied"));
        JsonNode body = mapper.readTree(response.getContentAsString());
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(body.get("title").asString()).isEqualTo("Forbidden");
        assertThat(body.get("error").asString()).isEqualTo("insufficient_scope");
    }
}
