package io.github.rmkrdev.entra.security.autoconfigure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Loads the signing keys once all singletons exist, so the first request finds them in memory. A failure is
 * logged and the keys are fetched on demand later; the startup self-check decides whether that is fatal.
 */
public class EntraJwksWarmer implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(EntraJwksWarmer.class);

    private final ObjectProvider<JWKSource<SecurityContext>> jwkSource;
    private final EntraSecurityProperties properties;
    private volatile int loadedKeys = -1;

    public EntraJwksWarmer(ObjectProvider<JWKSource<SecurityContext>> jwkSource, EntraSecurityProperties properties) {
        this.jwkSource = jwkSource;
        this.properties = properties;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (properties.getValidation().getMode() == EntraSecurityProperties.ValidationMode.INTROSPECTION) {
            return;
        }
        JWKSource<SecurityContext> source = jwkSource.getIfAvailable();
        if (source == null) {
            return;
        }
        long start = System.nanoTime();
        try {
            loadedKeys = source.get(new JWKSelector(new JWKMatcher.Builder().build()), null).size();
            log.debug("Pre-warmed {} Entra signing key(s) in {} ms", loadedKeys,
                    (System.nanoTime() - start) / 1_000_000);
        }
        catch (Exception ex) {
            log.warn("Unable to pre-warm the Entra signing keys ({}); they will be fetched on the first request",
                    ex.getMessage());
        }
    }

    /** Number of keys loaded at startup, or {@code -1} when none were. */
    public int getLoadedKeys() {
        return loadedKeys;
    }
}
