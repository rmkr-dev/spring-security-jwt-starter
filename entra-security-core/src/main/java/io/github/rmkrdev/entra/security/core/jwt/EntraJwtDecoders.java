package io.github.rmkrdev.entra.security.core.jwt;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;

/**
 * Builds a {@link NimbusJwtDecoder} hardened for Entra access tokens: RS256 only, keys from the
 * tenant JWKS (cached), and issuer, audience, tenant, expiry and not-before checks with a
 * configurable clock skew.
 */
public final class EntraJwtDecoders {

    private static final int JWKS_SIZE_LIMIT_BYTES = 512 * 1024;

    private EntraJwtDecoders() {
    }

    /**
     * A cached, rate-limited, retrying JWKS source for the given JWKS endpoint.
     */
    public static JWKSource<SecurityContext> jwkSource(URI jwkSetUri, Duration cacheTtl, Duration httpTimeout) {
        return jwkSource(jwkSetUri, cacheTtl, httpTimeout, EntraSecurityObservations.NO_OP);
    }

    /**
     * Same as {@link #jwkSource(URI, Duration, Duration)}, reporting each JWKS fetch to {@code observations}.
     * Cache hits are not reported. {@link EntraSecurityObservations#NO_OP} keeps the previous retriever.
     */
    public static JWKSource<SecurityContext> jwkSource(URI jwkSetUri, Duration cacheTtl, Duration httpTimeout,
            EntraSecurityObservations observations) {
        int timeoutMillis = (int) Math.min(Integer.MAX_VALUE, httpTimeout.toMillis());
        ResourceRetriever retriever = observations == null || observations == EntraSecurityObservations.NO_OP
                ? new DefaultResourceRetriever(timeoutMillis, timeoutMillis, JWKS_SIZE_LIMIT_BYTES)
                : new ObservingResourceRetriever(timeoutMillis, timeoutMillis, JWKS_SIZE_LIMIT_BYTES, observations);
        try {
            return JWKSourceBuilder.create(jwkSetUri.toURL(), retriever)
                    .cache(cacheTtl.toMillis(), httpTimeout.toMillis())
                    .retrying(true)
                    .build();
        }
        catch (MalformedURLException ex) {
            throw new IllegalArgumentException("Invalid JWKS URI: " + jwkSetUri, ex);
        }
    }

    /**
     * Creates the decoder.
     *
     * @param jwkSource  the signing keys
     * @param issuers    allowed {@code iss} values
     * @param audiences  allowed {@code aud} values
     * @param tenantId   when not {@code null}, the required {@code tid}
     * @param clockSkew  tolerance for {@code exp} and {@code nbf}
     */
    public static NimbusJwtDecoder create(JWKSource<SecurityContext> jwkSource, Collection<String> issuers,
            Collection<String> audiences, String tenantId, Duration clockSkew) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource));
        // Claims are validated by Spring Security validators below.
        processor.setJWTClaimsSetVerifier((claims, context) -> {
        });
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(validator(issuers, audiences, tenantId, clockSkew));
        return decoder;
    }

    /**
     * The composite validator used by {@link #create}.
     */
    public static OAuth2TokenValidator<Jwt> validator(Collection<String> issuers, Collection<String> audiences,
            String tenantId, Duration clockSkew) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new RequiredClaimsValidator(List.of("exp", "iss", "aud")));
        validators.add(new JwtTimestampValidator(clockSkew));
        validators.add(new EntraIssuerValidator(issuers));
        validators.add(new EntraAudienceValidator(audiences));
        if (tenantId != null) {
            validators.add(new EntraTenantValidator(tenantId));
        }
        return new DelegatingOAuth2TokenValidator<>(validators);
    }
}
