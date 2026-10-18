package io.github.rmkrdev.entra.security.autoconfigure.metrics;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import io.github.rmkrdev.entra.security.core.jwt.JwtAuthenticationOutcomes;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;

/**
 * Records JWT validation failures. Successes are recorded by {@code EntraJwtAuthenticationConverter}
 * so a token that fails authorization mapping is not counted twice.
 */
public final class ObservingJwtDecoder implements JwtDecoder {

    private final JwtDecoder delegate;
    private final EntraSecurityObservations observations;

    private ObservingJwtDecoder(JwtDecoder delegate, EntraSecurityObservations observations) {
        this.delegate = delegate;
        this.observations = observations;
    }

    /**
     * @return {@code delegate} when observations are disabled, otherwise a decoder that records failures
     */
    public static JwtDecoder wrap(JwtDecoder delegate, EntraSecurityObservations observations) {
        if (delegate == null || observations == null || observations == EntraSecurityObservations.NO_OP) {
            return delegate;
        }
        return new ObservingJwtDecoder(delegate, observations);
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            return delegate.decode(token);
        }
        catch (JwtException ex) {
            observations.jwtAuthentication(false, JwtAuthenticationOutcomes.reason(ex));
            throw ex;
        }
    }
}
