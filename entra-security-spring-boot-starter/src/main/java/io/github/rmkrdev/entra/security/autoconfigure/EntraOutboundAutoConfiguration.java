package io.github.rmkrdev.entra.security.autoconfigure;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.OutboundFlow;
import io.github.rmkrdev.entra.security.autoconfigure.keyvault.KeyVaultCredentialFactory;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.web.InteractionRequiredExceptionHandler;
import io.github.rmkrdev.entra.security.core.web.server.ServerInteractionRequiredExceptionHandler;

/**
 * Registers {@link EntraOutboundClients} for calling peer APIs with app-only tokens or on behalf of the
 * calling user, and the handlers that turn a required user interaction into a {@code 403} problem.
 */
@AutoConfiguration(after = EntraSecurityAutoConfiguration.class)
@ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
@EnableConfigurationProperties(EntraSecurityProperties.class)
public class EntraOutboundAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public EntraOutboundClients entraOutboundClients(EntraSecurityProperties properties, Environment environment,
            ObjectProvider<EntraTokenProviders> tokenProviders,
            ObjectProvider<EntraSecurityObservations> observations,
            ObjectProvider<KeyVaultCredentialFactory> keyVaultCredentials,
            ObjectProvider<EntraEndpoints> endpoints) {
        EntraTokenProviders providers = tokenProviders.getIfAvailable(() -> new EntraTokenProviders(properties,
                environment, EntraTokenProviders.defaultRestClient(properties), Clock.systemUTC(),
                observations.getIfAvailable(() -> EntraSecurityObservations.NO_OP),
                keyVaultCredentials.getIfAvailable(), endpoints.getIfAvailable()));
        Map<String, EntraOutboundClients.Client> clients = new LinkedHashMap<>();
        properties.getOutbound().getClients().forEach((name, config) -> clients.put(name,
                config.getFlow() == OutboundFlow.ON_BEHALF_OF
                        ? EntraOutboundClients.Client.onBehalfOf(name, config.getScope(), config.getBaseUrl(),
                                providers.createOnBehalfOf(config.getCredential()))
                        : new EntraOutboundClients.Client(name, config.getScope(), config.getBaseUrl(),
                                providers.create(config.getCredential()))));
        return new EntraOutboundClients(clients);
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass(name = "org.springframework.web.servlet.DispatcherServlet")
    static class ServletInteractionRequiredConfiguration {

        @Bean
        @ConditionalOnMissingBean
        InteractionRequiredExceptionHandler entraInteractionRequiredExceptionHandler() {
            return new InteractionRequiredExceptionHandler();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    @ConditionalOnClass(name = "org.springframework.web.reactive.DispatcherHandler")
    static class ReactiveInteractionRequiredConfiguration {

        @Bean
        @ConditionalOnMissingBean
        ServerInteractionRequiredExceptionHandler entraServerInteractionRequiredExceptionHandler() {
            return new ServerInteractionRequiredExceptionHandler();
        }
    }
}
