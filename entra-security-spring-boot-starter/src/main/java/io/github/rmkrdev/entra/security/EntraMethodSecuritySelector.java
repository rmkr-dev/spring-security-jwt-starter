package io.github.rmkrdev.entra.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.aop.config.AopConfigUtils;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.boot.web.context.reactive.ConfigurableReactiveWebEnvironment;
import org.springframework.boot.web.context.reactive.ReactiveWebApplicationContext;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;

import io.github.rmkrdev.entra.security.autoconfigure.EntraReactiveSecuredConfiguration;

/**
 * Picks the method security of {@link EnableEntraSecurity} for the application type: Spring Security's
 * {@code @EnableMethodSecurity} for servlet and non-web applications, {@code @EnableReactiveMethodSecurity}
 * plus reactive {@code @Secured} for WebFlux. Enabling the servlet interceptors in a WebFlux application would
 * deny every call, because they read the thread-local security context.
 */
class EntraMethodSecuritySelector implements ImportSelector, EnvironmentAware, ResourceLoaderAware {

    private Environment environment;
    private ResourceLoader resourceLoader;

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void setResourceLoader(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Override
    public String[] selectImports(AnnotationMetadata metadata) {
        Map<String, Object> raw = metadata.getAnnotationAttributes(EnableEntraSecurity.class.getName());
        AnnotationAttributes attributes = AnnotationAttributes.fromMap(raw);
        AdviceMode mode = attributes != null ? attributes.getEnum("mode") : AdviceMode.PROXY;
        boolean proxyTargetClass = attributes != null && attributes.getBoolean("proxyTargetClass");

        List<String> imports = new ArrayList<>();
        if (isReactive()) {
            imports.add(ReactiveMethodSecurity.class.getName());
        }
        else if (mode == AdviceMode.ASPECTJ) {
            imports.add(AspectJServletMethodSecurity.class.getName());
        }
        else {
            imports.add(ServletMethodSecurity.class.getName());
        }
        if (proxyTargetClass && mode == AdviceMode.PROXY) {
            imports.add(ProxyTargetClassRegistrar.class.getName());
        }
        return imports.toArray(String[]::new);
    }

    private boolean isReactive() {
        return environment instanceof ConfigurableReactiveWebEnvironment
                || resourceLoader instanceof ReactiveWebApplicationContext;
    }

    @Configuration(proxyBeanMethods = false)
    @EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
    static class ServletMethodSecurity {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true, mode = AdviceMode.ASPECTJ)
    static class AspectJServletMethodSecurity {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableReactiveMethodSecurity
    @Import(EntraReactiveSecuredConfiguration.class)
    static class ReactiveMethodSecurity {
    }

    /**
     * {@code proxyTargetClass = true}: class-based proxies, as on {@code @EnableMethodSecurity}.
     */
    static class ProxyTargetClassRegistrar implements ImportBeanDefinitionRegistrar {

        @Override
        public void registerBeanDefinitions(AnnotationMetadata metadata, BeanDefinitionRegistry registry) {
            AopConfigUtils.registerAutoProxyCreatorIfNecessary(registry);
            AopConfigUtils.forceAutoProxyCreatorToUseClassProxying(registry);
        }
    }
}
