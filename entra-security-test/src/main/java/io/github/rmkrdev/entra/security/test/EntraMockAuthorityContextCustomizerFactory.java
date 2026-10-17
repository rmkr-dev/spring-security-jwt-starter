package io.github.rmkrdev.entra.security.test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.test.context.ContextConfigurationAttributes;
import org.springframework.test.context.ContextCustomizer;
import org.springframework.test.context.ContextCustomizerFactory;
import org.springframework.test.context.MergedContextConfiguration;
import org.springframework.test.context.TestContextAnnotationUtils;

/**
 * Applies {@link AutoConfigureEntraMockAuthority}. Registered in {@code META-INF/spring.factories}.
 */
public class EntraMockAuthorityContextCustomizerFactory implements ContextCustomizerFactory {

    static final String PROPERTY_SOURCE_NAME = "entraMockAuthority";

    @Override
    public ContextCustomizer createContextCustomizer(Class<?> testClass,
            List<ContextConfigurationAttributes> configAttributes) {
        if (TestContextAnnotationUtils.hasAnnotation(testClass, AutoConfigureEntraMockAuthority.class)) {
            return new Customizer();
        }
        return null;
    }

    /**
     * Stateless, so every annotated test class shares the same cached application context key part.
     */
    static final class Customizer implements ContextCustomizer {

        @Override
        public void customizeContext(ConfigurableApplicationContext context, MergedContextConfiguration config) {
            EntraMockAuthority authority = EntraMockAuthority.shared();
            ConfigurableEnvironment environment = context.getEnvironment();

            Map<String, Object> properties = new LinkedHashMap<>();
            properties.put("entra.security.authority-host", authority.baseUrl());
            properties.put("entra.security.jwk-set-uri",
                    authority.baseUrl() + "/${entra.security.tenant-id}/discovery/v2.0/keys");
            properties.put("entra.security.graph.base-url", authority.baseUrl());
            environment.getPropertySources().addFirst(new MapPropertySource(PROPERTY_SOURCE_NAME, properties));

            ConfigurableListableBeanFactory beanFactory = context.getBeanFactory();
            beanFactory.registerSingleton("entraMockAuthority", authority);
            if (beanFactory instanceof BeanDefinitionRegistry registry) {
                RootBeanDefinition tokens = new RootBeanDefinition(EntraTestTokens.class);
                tokens.setInstanceSupplier(() -> fromEnvironment(authority, environment));
                registry.registerBeanDefinition("entraTestTokens", tokens);
            }
        }

        static EntraTestTokens fromEnvironment(EntraMockAuthority authority, ConfigurableEnvironment environment) {
            String tenantId = environment.getProperty("entra.security.tenant-id");
            String clientId = environment.getProperty("entra.security.audiences[0]",
                    environment.getProperty("entra.security.client-id"));
            if (tenantId == null || tenantId.isBlank() || clientId == null || clientId.isBlank()) {
                throw new IllegalStateException("@AutoConfigureEntraMockAuthority needs entra.security.tenant-id and "
                        + "entra.security.client-id in the test configuration");
            }
            return authority.tokens(tenantId, clientId);
        }

        @Override
        public boolean equals(Object other) {
            return other != null && other.getClass() == getClass();
        }

        @Override
        public int hashCode() {
            return getClass().hashCode();
        }
    }
}
