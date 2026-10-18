package io.github.rmkrdev.entra.security.core.token;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Posts a token request form to the Entra v2 token endpoint and turns the answer into a token or an
 * {@link EntraTokenAcquisitionException}. Shared by the client-credentials and on-behalf-of providers.
 */
final class TokenEndpointClient {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern AADSTS = Pattern.compile("AADSTS(\\d+)");

    private final URI tokenEndpoint;
    private final String clientId;
    private final RestClient restClient;
    private final Clock clock;

    TokenEndpointClient(URI tokenEndpoint, String clientId, RestClient restClient, Clock clock) {
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.restClient = restClient;
        this.clock = clock;
    }

    /**
     * Sends the form.
     *
     * @param errors turns an error response into the exception to throw
     */
    IssuedToken request(MultiValueMap<String, String> form,
            Function<TokenError, ? extends EntraTokenAcquisitionException> errors) {
        Instant requestedAt = clock.instant();
        JsonNode body;
        try {
            body = restClient.post()
                    .uri(tokenEndpoint)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(form)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (request, response) -> {
                        throw errors.apply(parseError(response.getStatusCode().value(), response.getBody()));
                    })
                    .body(JsonNode.class);
        }
        catch (EntraTokenAcquisitionException ex) {
            throw ex;
        }
        catch (RestClientException ex) {
            throw new EntraTokenAcquisitionException("Token request to " + tokenEndpoint + " failed: "
                    + ex.getMessage(), null, ex);
        }
        if (body == null || !body.hasNonNull("access_token")) {
            throw new EntraTokenAcquisitionException("Token response from " + tokenEndpoint
                    + " did not contain an access_token", null, null);
        }
        long expiresIn = body.path("expires_in").asLong(300);
        return new IssuedToken(new AccessToken(body.get("access_token").asText(), requestedAt.plusSeconds(expiresIn)),
                Duration.ofSeconds(expiresIn));
    }

    /** The default exception for an error response. */
    EntraTokenAcquisitionException defaultError(TokenError error) {
        return new EntraTokenAcquisitionException(message("Token request", error), error.error(), null);
    }

    /** {@code {label} to {endpoint} for client {id} failed with HTTP {status}: {error} - {description}}. */
    String message(String label, TokenError error) {
        StringBuilder message = new StringBuilder(label).append(" to ").append(tokenEndpoint)
                .append(" for client ").append(clientId).append(" failed with HTTP ").append(error.status());
        if (error.error() != null) {
            message.append(": ").append(error.error());
        }
        if (error.description() != null) {
            String description = error.description();
            message.append(" - ").append(description.lines().findFirst().orElse(description));
        }
        return message.toString();
    }

    /**
     * When to renew a token: {@code refreshSkew} before it expires, but never earlier than halfway through
     * its lifetime, so short-lived tokens are not fetched on every call.
     */
    static Instant refreshAt(IssuedToken issued, Duration refreshSkew) {
        Duration half = issued.lifetime().dividedBy(2);
        Duration skew = refreshSkew.compareTo(half) > 0 ? half : refreshSkew;
        return issued.token().expiresAt().minus(skew);
    }

    private static TokenError parseError(int status, InputStream bodyStream) {
        String error = null;
        String description = null;
        String suberror = null;
        String claims = null;
        List<Integer> codes = new ArrayList<>();
        try (InputStream in = bodyStream) {
            JsonNode node = JSON.readTree(in);
            if (node != null) {
                error = node.path("error").asText(null);
                description = node.path("error_description").asText(null);
                suberror = node.path("suberror").asText(null);
                claims = node.path("claims").asText(null);
                node.path("error_codes").forEach(code -> {
                    if (code.canConvertToInt()) {
                        codes.add(code.asInt());
                    }
                });
            }
        }
        catch (IOException | RuntimeException ignored) {
            // non-JSON error body
        }
        if (codes.isEmpty() && description != null) {
            Matcher matcher = AADSTS.matcher(description);
            if (matcher.find()) {
                codes.add(Integer.parseInt(matcher.group(1)));
            }
        }
        return new TokenError(status, error, description, suberror, claims, Collections.unmodifiableList(codes));
    }

    /** A token and the lifetime Entra gave it. */
    record IssuedToken(AccessToken token, Duration lifetime) {
    }

    /**
     * The fields of an Entra token error response.
     *
     * @param status      HTTP status
     * @param error       OAuth error code, such as {@code invalid_grant}
     * @param description {@code error_description}
     * @param suberror    {@code suberror}, such as {@code consent_required}
     * @param claims      the claims challenge, if any
     * @param errorCodes  the {@code AADSTS} codes
     */
    record TokenError(int status, String error, String description, String suberror, String claims,
            List<Integer> errorCodes) {
    }
}
