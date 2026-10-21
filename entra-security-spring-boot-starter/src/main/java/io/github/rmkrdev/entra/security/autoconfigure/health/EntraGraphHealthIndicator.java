package io.github.rmkrdev.entra.security.autoconfigure.health;

import java.net.URI;

import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;

/**
 * Reports whether Microsoft Graph accepts the configured application credential.
 * <p>
 * Registered only when {@code entra.security.graph.overage-enabled=true}, as Actuator component
 * {@code entraGraph}. The probe is {@code GET {graph.base-url}/v1.0/} with an app-only token. It is
 * not a group lookup and does not increment {@code entra.security.graph.lookups}.
 */
public class EntraGraphHealthIndicator extends AbstractHealthIndicator {

    private final EntraTokenProvider tokenProvider;
    private final RestClient restClient;
    private final String scope;
    private final URI probeUri;

    public EntraGraphHealthIndicator(EntraTokenProvider tokenProvider, RestClient restClient, URI graphBaseUrl,
            String scope) {
        super("Entra Graph health check failed");
        this.tokenProvider = tokenProvider;
        this.restClient = restClient;
        this.scope = scope;
        this.probeUri = probeUri(graphBaseUrl);
    }

    static URI probeUri(URI graphBaseUrl) {
        String base = graphBaseUrl.toString();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return URI.create(base + "/v1.0/");
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        contribute(tokenProvider, restClient, probeUri, scope, builder);
    }

    static void contribute(EntraTokenProvider tokenProvider, RestClient restClient, URI probeUri, String scope,
            Health.Builder builder) {
        String token;
        try {
            token = tokenProvider.getToken(scope).value();
        }
        catch (RuntimeException ex) {
            builder.down().withDetail("reason", "token").withException(ex);
            return;
        }
        try {
            restClient.get()
                    .uri(probeUri)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .toBodilessEntity();
            builder.up();
        }
        catch (RestClientResponseException ex) {
            int status = ex.getStatusCode().value();
            String reason = status == 401 || status == 403 ? "unauthorized" : "error";
            builder.down().withDetail("reason", reason).withDetail("status", status);
        }
        catch (Exception ex) {
            builder.down().withDetail("reason", "unreachable").withException(ex);
        }
    }
}
