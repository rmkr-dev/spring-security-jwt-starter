package io.github.rmkrdev.entra.security.autoconfigure.health;

import java.net.URI;

import org.springframework.boot.health.contributor.AbstractReactiveHealthIndicator;
import org.springframework.boot.health.contributor.Health;
import org.springframework.web.client.RestClient;

import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * WebFlux form of {@link EntraGraphHealthIndicator}. The token request and Graph probe are blocking, so they
 * run on {@code boundedElastic}. Actuator exposes the bean as {@code entraGraph}.
 */
public class EntraGraphReactiveHealthIndicator extends AbstractReactiveHealthIndicator {

    private final EntraTokenProvider tokenProvider;
    private final RestClient restClient;
    private final String scope;
    private final URI probeUri;

    public EntraGraphReactiveHealthIndicator(EntraTokenProvider tokenProvider, RestClient restClient,
            URI graphBaseUrl, String scope) {
        super("Entra Graph health check failed");
        this.tokenProvider = tokenProvider;
        this.restClient = restClient;
        this.scope = scope;
        this.probeUri = EntraGraphHealthIndicator.probeUri(graphBaseUrl);
    }

    @Override
    protected Mono<Health> doHealthCheck(Health.Builder builder) {
        return Mono.fromCallable(() -> {
            EntraGraphHealthIndicator.contribute(tokenProvider, restClient, probeUri, scope, builder);
            return builder.build();
        }).subscribeOn(Schedulers.boundedElastic());
    }
}
