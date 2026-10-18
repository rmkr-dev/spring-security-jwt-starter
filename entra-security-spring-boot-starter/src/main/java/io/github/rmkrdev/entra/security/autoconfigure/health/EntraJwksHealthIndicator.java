package io.github.rmkrdev.entra.security.autoconfigure.health;

import java.util.List;

import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Reports whether the tenant JWKS can be loaded and contains at least one RSA signing key.
 * <p>
 * Contributes to Actuator as {@code entraJwks} (the bean name with the {@code HealthIndicator} suffix
 * removed). A failure marks readiness down; it does not by itself fail liveness.
 */
public class EntraJwksHealthIndicator extends AbstractHealthIndicator {

    private final JWKSource<SecurityContext> jwkSource;

    public EntraJwksHealthIndicator(JWKSource<SecurityContext> jwkSource) {
        super("Entra JWKS health check failed");
        this.jwkSource = jwkSource;
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        try {
            List<JWK> keys = jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
            int usable = 0;
            if (keys != null) {
                for (JWK key : keys) {
                    if (usableSigningKey(key)) {
                        usable++;
                    }
                }
            }
            if (usable == 0) {
                builder.down().withDetail("reason", "no_signing_keys").withDetail("keys", 0);
                return;
            }
            builder.up().withDetail("keys", usable);
        }
        catch (Exception ex) {
            builder.down().withDetail("reason", "unreachable").withException(ex);
        }
    }

    private static boolean usableSigningKey(JWK key) {
        if (!(key instanceof RSAKey rsa) || rsa.getModulus() == null) {
            return false;
        }
        KeyUse use = key.getKeyUse();
        return use == null || use == KeyUse.SIGNATURE;
    }
}
