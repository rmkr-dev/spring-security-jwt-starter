package io.github.rmkrdev.entra.security;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties;

/**
 * Warms the JWKS cache and logs the effective Entra configuration once the context has started.
 */
public class EntraSecurityPreloader implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(EntraSecurityPreloader.class);

    private final ObjectProvider<JWKSource<SecurityContext>> jwkSource;
    private final ObjectProvider<EntraSecurityProperties> properties;
    private final boolean preloadJwks;
    private final boolean failOnJwksError;
    private volatile int loadedKeys = -1;

    public EntraSecurityPreloader(ObjectProvider<JWKSource<SecurityContext>> jwkSource,
            ObjectProvider<EntraSecurityProperties> properties, boolean preloadJwks, boolean failOnJwksError) {
        this.jwkSource = jwkSource;
        this.properties = properties;
        this.preloadJwks = preloadJwks;
        this.failOnJwksError = failOnJwksError;
    }

    @Override
    public void afterSingletonsInstantiated() {
        EntraSecurityProperties config = properties.getIfAvailable();
        if (config == null || !config.isEnabled()) {
            log.warn("@EnableEntraSecurity is present but the Entra security auto-configuration is not active");
            return;
        }
        log.info("Entra security active: tenant={} clientId={} audiences={} issuers={} publicPaths={} "
                + "groupMappings={} appRoleMappings={} clientMappings={} graphOverage={} outboundClients={}",
                config.getTenantId(), config.getClientId(), config.resolveAudiences(), config.resolveIssuers(),
                config.getPublicPaths(), config.resolveGroupRoleMappings().size(),
                config.resolveAppRoleMappings().size(), config.resolveClientRoleMappings().size(),
                config.getGraph().isOverageEnabled(),
                config.getOutbound().getClients().keySet());
        JWKSource<SecurityContext> source = jwkSource.getIfAvailable();
        if (!preloadJwks || source == null) {
            return;
        }
        try {
            List<JWK> keys = source.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
            loadedKeys = keys.size();
            log.info("Preloaded {} Entra signing key(s) from {}", loadedKeys, config.resolveJwkSetUri());
        }
        catch (Exception ex) {
            String message = "Unable to load Entra signing keys from " + config.resolveJwkSetUri()
                    + ": check entra.security.tenant-id, entra.security.jwk-set-uri and network egress to Entra";
            if (failOnJwksError) {
                throw new IllegalStateException(message, ex);
            }
            log.warn("{} ({}); keys will be fetched on the first request", message, ex.getMessage());
        }
    }

    /**
     * Number of keys loaded at startup, or {@code -1} if no preload happened.
     */
    public int getLoadedKeys() {
        return loadedKeys;
    }
}
