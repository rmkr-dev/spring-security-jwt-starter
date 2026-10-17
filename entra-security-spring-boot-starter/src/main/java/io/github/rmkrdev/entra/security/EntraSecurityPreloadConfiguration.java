package io.github.rmkrdev.entra.security;

import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties;

/**
 * Registers the {@link EntraSecurityPreloader} for {@link EnableEntraSecurity}.
 */
@Configuration(proxyBeanMethods = false)
public class EntraSecurityPreloadConfiguration implements ImportAware {

    private boolean preloadJwks = true;
    private boolean failOnJwksError = false;

    @Override
    public void setImportMetadata(AnnotationMetadata metadata) {
        Map<String, Object> raw = metadata.getAnnotationAttributes(EnableEntraSecurity.class.getName());
        AnnotationAttributes attributes = AnnotationAttributes.fromMap(raw);
        if (attributes != null) {
            this.preloadJwks = attributes.getBoolean("preloadJwks");
            this.failOnJwksError = attributes.getBoolean("failOnJwksError");
        }
    }

    @Bean
    public EntraSecurityPreloader entraSecurityPreloader(
            ObjectProvider<JWKSource<SecurityContext>> jwkSource,
            ObjectProvider<EntraSecurityProperties> properties) {
        return new EntraSecurityPreloader(jwkSource, properties, preloadJwks, failOnJwksError);
    }
}
