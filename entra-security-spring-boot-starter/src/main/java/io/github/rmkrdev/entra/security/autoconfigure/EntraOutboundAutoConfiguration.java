package io.github.rmkrdev.entra.security.autoconfigure;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Registers {@link EntraOutboundClients} for calling peer APIs with app-only tokens.
 */
@AutoConfiguration(after = EntraSecurityAutoConfiguration.class)
@ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(EntraSecurityProperties.class)
public class EntraOutboundAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public EntraOutboundClients entraOutboundClients(EntraSecurityProperties properties, Environment environment) {
        EntraTokenProviders providers = new EntraTokenProviders(properties, environment);
        Map<String, EntraOutboundClients.Client> clients = new LinkedHashMap<>();
        properties.getOutbound().getClients().forEach((name, config) -> clients.put(name,
                new EntraOutboundClients.Client(name, config.getScope(), config.getBaseUrl(),
                        providers.create(config.getCredential()))));
        return new EntraOutboundClients(clients);
    }
}
