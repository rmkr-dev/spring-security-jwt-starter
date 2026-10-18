package io.github.rmkrdev.entra.security.core.jwt;

import java.time.Duration;
import java.util.Collection;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

/**
 * A {@link ReactiveJwtDecoder} for WebFlux resource servers that runs the servlet decoder built by
 * {@link EntraJwtDecoders}, so both stacks accept exactly the same tokens: RS256 only, the same JWKS cache,
 * and the same issuer, audience, tenant, expiry and not-before checks.
 * <p>
 * Decoding runs on a {@link Scheduler} suited to blocking work (by default {@link Schedulers#boundedElastic()})
 * because a JWKS refresh is a blocking HTTP call. Errors are the same {@link JwtException}s the servlet
 * decoder throws.
 */
public final class EntraReactiveJwtDecoder implements ReactiveJwtDecoder {

    private final JwtDecoder delegate;
    private final Scheduler scheduler;

    public EntraReactiveJwtDecoder(JwtDecoder delegate) {
        this(delegate, Schedulers.boundedElastic());
    }

    public EntraReactiveJwtDecoder(JwtDecoder delegate, Scheduler scheduler) {
        this.delegate = delegate;
        this.scheduler = scheduler;
    }

    /**
     * Creates the decoder with the same arguments as {@link EntraJwtDecoders#create}.
     */
    public static EntraReactiveJwtDecoder create(JWKSource<SecurityContext> jwkSource, Collection<String> issuers,
            Collection<String> audiences, String tenantId, Duration clockSkew) {
        return new EntraReactiveJwtDecoder(EntraJwtDecoders.create(jwkSource, issuers, audiences, tenantId,
                clockSkew));
    }

    @Override
    public Mono<Jwt> decode(String token) throws JwtException {
        return Mono.fromCallable(() -> delegate.decode(token)).subscribeOn(scheduler);
    }

    /**
     * The blocking decoder this one delegates to.
     */
    public JwtDecoder getDelegate() {
        return delegate;
    }
}
