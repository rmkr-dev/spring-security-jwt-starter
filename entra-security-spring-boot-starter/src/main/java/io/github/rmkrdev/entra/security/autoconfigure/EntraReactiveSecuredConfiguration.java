package io.github.rmkrdev.entra.security.autoconfigure;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeReactiveMethodInterceptor;
import org.springframework.security.authorization.method.SecuredAuthorizationManager;
import org.springframework.security.core.Authentication;

import reactor.core.publisher.Mono;

/**
 * {@code @Secured} for WebFlux. Spring Security's {@code @EnableReactiveMethodSecurity} covers
 * {@code @PreAuthorize}, {@code @PostAuthorize}, {@code @PreFilter} and {@code @PostFilter} only; this adds
 * {@code @Secured} with the same semantics as on the servlet stack, for methods that return a
 * {@code Mono} or {@code Flux}.
 * <p>
 * Imported by the reactive auto-configuration and by {@code @EnableEntraSecurity} in reactive applications.
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
public class EntraReactiveSecuredConfiguration {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static AuthorizationManagerBeforeReactiveMethodInterceptor entraReactiveSecuredAuthorizationMethodInterceptor() {
        AuthorizationManagerBeforeReactiveMethodInterceptor interceptor =
                new AuthorizationManagerBeforeReactiveMethodInterceptor(securedPointcut(),
                        new SecuredReactiveAuthorizationManager());
        interceptor.setOrder(AuthorizationInterceptorsOrder.SECURED.getOrder());
        return interceptor;
    }

    private static Pointcut securedPointcut() {
        return new ComposablePointcut(new AnnotationMatchingPointcut(null, Secured.class, true))
                .union(new AnnotationMatchingPointcut(Secured.class, true));
    }

    /**
     * Runs Spring Security's {@link SecuredAuthorizationManager} against the reactive authentication. No
     * authentication means no decision, which the interceptor treats as denied.
     * <p>
     * Only {@code check} is implemented: it is the one abstract method on Spring Security 6.3 to 6.5, and from 6.4
     * the default {@code authorize} delegates to it. {@code SecuredAuthorizationManager} itself only implements
     * {@code check}, so the result is the same on every supported version.
     */
    static final class SecuredReactiveAuthorizationManager implements ReactiveAuthorizationManager<MethodInvocation> {

        private final SecuredAuthorizationManager secured = new SecuredAuthorizationManager();

        @Override
        @Deprecated
        public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, MethodInvocation invocation) {
            return authentication.flatMap(auth -> Mono.justOrEmpty(secured.check(() -> auth, invocation)));
        }
    }
}
