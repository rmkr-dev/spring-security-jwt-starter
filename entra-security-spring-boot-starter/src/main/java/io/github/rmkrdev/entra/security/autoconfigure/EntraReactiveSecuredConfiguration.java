package io.github.rmkrdev.entra.security.autoconfigure;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeReactiveMethodInterceptor;
import org.springframework.security.authorization.method.Jsr250AuthorizationManager;
import org.springframework.security.authorization.method.SecuredAuthorizationManager;
import org.springframework.security.core.Authentication;

import reactor.core.publisher.Mono;

/**
 * {@code @Secured} and {@code @RolesAllowed} for WebFlux. Spring Security's
 * {@code @EnableReactiveMethodSecurity} covers {@code @PreAuthorize}, {@code @PostAuthorize},
 * {@code @PreFilter} and {@code @PostFilter} only. This adds the same semantics as on the servlet stack,
 * for methods that return a {@code Mono} or {@code Flux}.
 * <p>
 * Spring Security 7 removed {@code ReactiveAuthorizationManager#check}. Both adapters implement
 * {@code authorize}.
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
                        new BlockingAuthorizationAdapter(new SecuredAuthorizationManager()));
        interceptor.setOrder(AuthorizationInterceptorsOrder.SECURED.getOrder());
        return interceptor;
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static AuthorizationManagerBeforeReactiveMethodInterceptor entraReactiveJsr250AuthorizationMethodInterceptor() {
        AuthorizationManagerBeforeReactiveMethodInterceptor interceptor =
                new AuthorizationManagerBeforeReactiveMethodInterceptor(jsr250Pointcut(),
                        new BlockingAuthorizationAdapter(new Jsr250AuthorizationManager()));
        interceptor.setOrder(AuthorizationInterceptorsOrder.JSR250.getOrder());
        return interceptor;
    }

    private static Pointcut securedPointcut() {
        return new ComposablePointcut(new AnnotationMatchingPointcut(null, Secured.class, true))
                .union(new AnnotationMatchingPointcut(Secured.class, true));
    }

    private static Pointcut jsr250Pointcut() {
        Pointcut pointcut = annotated(RolesAllowed.class);
        pointcut = new ComposablePointcut(pointcut).union(annotated(PermitAll.class)).union(annotated(DenyAll.class));
        return pointcut;
    }

    private static Pointcut annotated(Class<? extends java.lang.annotation.Annotation> annotation) {
        return new ComposablePointcut(new AnnotationMatchingPointcut(null, annotation, true))
                .union(new AnnotationMatchingPointcut(annotation, true));
    }

    /**
     * Runs a servlet {@link AuthorizationManager} against the reactive authentication. No authentication means
     * no decision, which the interceptor treats as denied. A {@code null} result from the delegate abstains.
     */
    static final class BlockingAuthorizationAdapter implements ReactiveAuthorizationManager<MethodInvocation> {

        private final AuthorizationManager<MethodInvocation> delegate;

        BlockingAuthorizationAdapter(AuthorizationManager<MethodInvocation> delegate) {
            this.delegate = delegate;
        }

        @Override
        public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, MethodInvocation invocation) {
            return authentication.flatMap(auth -> Mono.justOrEmpty(delegate.authorize(() -> auth, invocation)));
        }
    }
}
