package io.github.rmkrdev.entra.security.autoconfigure.health;

import org.springframework.boot.health.contributor.AbstractReactiveHealthIndicator;
import org.springframework.boot.health.contributor.Health;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * WebFlux form of {@link EntraJwksHealthIndicator}. The JWKS read is blocking, so it runs on
 * {@code boundedElastic}. Actuator exposes the bean as {@code entraJwks}.
 */
public class EntraJwksReactiveHealthIndicator extends AbstractReactiveHealthIndicator {

    private final JWKSource<SecurityContext> jwkSource;

    public EntraJwksReactiveHealthIndicator(JWKSource<SecurityContext> jwkSource) {
        super("Entra JWKS health check failed");
        this.jwkSource = jwkSource;
    }

    @Override
    protected Mono<Health> doHealthCheck(Health.Builder builder) {
        return Mono.fromCallable(() -> {
            EntraJwksHealthIndicator.contribute(jwkSource, builder);
            return builder.build();
        }).subscribeOn(Schedulers.boundedElastic());
    }
}
