package io.github.rmkrdev.entra.security.core.web.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsAccessDeniedHandler;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsAuthenticationEntryPoint;
import io.github.rmkrdev.entra.security.core.web.ProblemDetailsWriter;
import reactor.core.publisher.Mono;

/**
 * The WebFlux handlers answer exactly like the servlet ones: same status, header and body.
 */
class ServerProblemDetailsTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final ServerProblemDetailsWriter writer = new ServerProblemDetailsWriter(mapper);

    @Test
    void unauthorizedInvalidTokenMatchesServlet() throws Exception {
        assertSameAsServlet(new InvalidBearerTokenException("Jwt expired"));
        MockServerWebExchange exchange = exchange("/api/x");
        new ServerProblemDetailsAuthenticationEntryPoint(writer)
                .commence(exchange, new InvalidBearerTokenException("Jwt expired")).block();
        JsonNode body = body(exchange.getResponse());
        assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(401);
        assertThat(exchange.getResponse().getHeaders().getContentType())
                .isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(exchange.getResponse().getHeaders().getFirst("WWW-Authenticate"))
                .startsWith("Bearer").contains("invalid_token");
        assertThat(body.get("detail").asText()).isEqualTo("Jwt expired");
        assertThat(body.get("instance").asText()).isEqualTo("/api/x");
        assertThat(body.get("error").asText()).isEqualTo("invalid_token");
    }

    @Test
    void unauthorizedMissingTokenMatchesServlet() throws Exception {
        assertSameAsServlet(new InsufficientAuthenticationException("Full authentication is required"));
    }

    @Test
    void forbiddenMatchesServletForBearerCallers() throws Exception {
        EntraAuthenticationToken caller = caller();
        MockServerWebExchange exchange = exchange("/api/y");
        ServerWebExchange withPrincipal = exchange.mutate().principal(Mono.just(caller)).build();
        new ServerProblemDetailsAccessDeniedHandler(writer)
                .handle(withPrincipal, new AccessDeniedException("Access Denied")).block();

        MockHttpServletRequest servletRequest = new MockHttpServletRequest("GET", "/api/y");
        servletRequest.setUserPrincipal(caller);
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        new ProblemDetailsAccessDeniedHandler(new ProblemDetailsWriter(mapper)).handle(servletRequest,
                servletResponse, new AccessDeniedException("Access Denied"));

        assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(403);
        assertThat(exchange.getResponse().getHeaders().getFirst("WWW-Authenticate"))
                .isEqualTo(servletResponse.getHeader("WWW-Authenticate"))
                .contains("insufficient_scope");
        assertThat(body(exchange.getResponse())).isEqualTo(mapper.readTree(servletResponse.getContentAsString()));
    }

    @Test
    void committedResponseIsLeftAlone() {
        MockServerWebExchange exchange = exchange("/api/z");
        exchange.getResponse().setComplete().block();
        writer.write(exchange, org.springframework.http.HttpStatus.UNAUTHORIZED, "x", null).block();
        assertThat(exchange.getResponse().getBodyAsString().block()).isNullOrEmpty();
    }

    private void assertSameAsServlet(AuthenticationException error) throws Exception {
        MockServerWebExchange exchange = exchange("/api/x");
        new ServerProblemDetailsAuthenticationEntryPoint(writer).commence(exchange, error).block();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        new ProblemDetailsAuthenticationEntryPoint(new ProblemDetailsWriter(mapper))
                .commence(new MockHttpServletRequest("GET", "/api/x"), servletResponse, error);

        assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(servletResponse.getStatus());
        assertThat(exchange.getResponse().getHeaders().getFirst("WWW-Authenticate"))
                .isEqualTo(servletResponse.getHeader("WWW-Authenticate"));
        assertThat(body(exchange.getResponse())).isEqualTo(mapper.readTree(servletResponse.getContentAsString()));
    }

    private static MockServerWebExchange exchange(String path) {
        return MockServerWebExchange.from(MockServerHttpRequest.get(path));
    }

    private JsonNode body(MockServerHttpResponse response) throws Exception {
        return mapper.readTree(response.getBodyAsString().block());
    }

    private static EntraAuthenticationToken caller() {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "RS256").claim("oid", "o-1")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        EntraPrincipal principal = new EntraPrincipal(PrincipalType.USER, "t", "o-1", "s", "a", null, null,
                Set.of(), Set.of(), Set.of(), Set.of(), "2.0");
        return new EntraAuthenticationToken(jwt, principal, List.of());
    }
}
