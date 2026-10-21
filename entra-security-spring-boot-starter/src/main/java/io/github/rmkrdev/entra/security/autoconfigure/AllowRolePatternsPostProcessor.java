package io.github.rmkrdev.entra.security.autoconfigure;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.Pointcut;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;
import org.springframework.util.ClassUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import io.github.rmkrdev.entra.security.core.authority.AllowRolePatterns;
import io.github.rmkrdev.entra.security.core.decision.AuthDecision;

/**
 * Applies {@code entra.security.authorization.allow-role-patterns} to method security: a caller with a role that
 * matches a pattern passes {@code @Secured}, {@code @PreAuthorize}, {@code @PostAuthorize} and
 * {@code @RolesAllowed} checks. Everyone else gets the normal check.
 * <p>
 * Each method-security interceptor is wrapped rather than replaced, so its pointcut, order and configuration
 * (expression handler, role hierarchy) stay as they are. {@code @PreFilter} and {@code @PostFilter} are not
 * affected. A grant is logged at INFO the first time per role, pattern and method, at DEBUG afterwards, and
 * shows up in the audit line as {@code reason=role_pattern}.
 */
public final class AllowRolePatternsPostProcessor implements BeanPostProcessor, PriorityOrdered {

    static final String REASON = "role_pattern";
    private static final Logger log = LoggerFactory.getLogger(AllowRolePatternsPostProcessor.class);
    private static final Set<String> INTERCEPTORS = Set.of("preAuthorizeAuthorizationMethodInterceptor",
            "postAuthorizeAuthorizationMethodInterceptor", "securedAuthorizationMethodInterceptor",
            "jsr250AuthorizationMethodInterceptor", "entraReactiveSecuredAuthorizationMethodInterceptor",
            "entraReactiveJsr250AuthorizationMethodInterceptor");
    private static final boolean REACTOR = ClassUtils.isPresent("reactor.core.publisher.Mono",
            AllowRolePatternsPostProcessor.class.getClassLoader());

    private final AllowRolePatterns patterns;
    private final Map<String, Boolean> announced = new ConcurrentHashMap<>();

    public AllowRolePatternsPostProcessor(AllowRolePatterns patterns) {
        this.patterns = patterns;
    }

    /** Registered before the AOP auto-proxy creator, so it sees the interceptors before they become advice. */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (!patterns.isEmpty() && INTERCEPTORS.contains(beanName) && bean instanceof AuthorizationAdvisor advisor) {
            return new Granting(advisor);
        }
        return bean;
    }

    void granted(AllowRolePatterns.Match match, MethodInvocation invocation) {
        String method = invocation.getMethod().getDeclaringClass().getSimpleName() + "."
                + invocation.getMethod().getName();
        if (announced.putIfAbsent(match.role() + "|" + match.pattern() + "|" + method, Boolean.TRUE) == null) {
            log.info("Access to {} granted by entra.security.authorization.allow-role-patterns: role {} matches '{}'",
                    method, match.role(), match.pattern());
        }
        else {
            log.debug("Access to {} granted by allow-role-patterns: role {} matches '{}'", method, match.role(),
                    match.pattern());
        }
    }

    private final class Granting implements AuthorizationAdvisor {

        private final AuthorizationAdvisor delegate;

        Granting(AuthorizationAdvisor delegate) {
            this.delegate = delegate;
        }

        @Override
        public Object invoke(MethodInvocation invocation) throws Throwable {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null && REACTOR
                    && Publisher.class.isAssignableFrom(invocation.getMethod().getReturnType())) {
                return Reactive.invoke(this, invocation);
            }
            Optional<AllowRolePatterns.Match> match = match(authentication);
            if (match.isEmpty()) {
                return delegate.invoke(invocation);
            }
            granted(match.get(), invocation);
            RequestAttributes request = RequestContextHolder.getRequestAttributes();
            if (request != null) {
                request.setAttribute(AuthDecision.REASON_ATTRIBUTE, REASON, RequestAttributes.SCOPE_REQUEST);
            }
            return invocation.proceed();
        }

        AllowRolePatternsPostProcessor outer() {
            return AllowRolePatternsPostProcessor.this;
        }

        Optional<AllowRolePatterns.Match> match(Authentication authentication) {
            return authentication == null || !authentication.isAuthenticated() ? Optional.empty()
                    : patterns.match(authentication.getAuthorities());
        }

        @Override
        public Pointcut getPointcut() {
            return delegate.getPointcut();
        }

        @Override
        public Advice getAdvice() {
            return this;
        }

        @Override
        public boolean isPerInstance() {
            return true;
        }

        @Override
        public int getOrder() {
            return delegate.getOrder();
        }
    }

    /** Kept apart so Reactor is only loaded when it is on the classpath. */
    private static final class Reactive {

        @SuppressWarnings({ "unchecked", "rawtypes" })
        static Object invoke(Granting granting, MethodInvocation invocation) {
            reactor.core.publisher.Mono<Optional<AllowRolePatterns.Match>> match = ReactiveSecurityContextHolder
                    .getContext().mapNotNull(SecurityContext::getAuthentication).map(granting::match)
                    .defaultIfEmpty(Optional.empty());
            java.util.function.Function<Optional<AllowRolePatterns.Match>, Publisher<?>> next = found -> {
                try {
                    if (found.isEmpty()) {
                        return (Publisher<?>) granting.delegate.invoke(invocation);
                    }
                    granting.outer().granted(found.get(), invocation);
                    return reactor.core.publisher.Mono.deferContextual(context -> {
                        context.<AtomicReference<String>>getOrEmpty(AuthDecision.REASON_ATTRIBUTE)
                                .ifPresent(holder -> holder.set(REASON));
                        return reactor.core.publisher.Mono.empty();
                    }).thenMany(proceed(invocation));
                }
                catch (Throwable ex) {
                    return reactor.core.publisher.Mono.error(ex);
                }
            };
            if (reactor.core.publisher.Mono.class.isAssignableFrom(invocation.getMethod().getReturnType())) {
                return match.flatMap(found -> reactor.core.publisher.Mono.from((Publisher) next.apply(found)));
            }
            return match.flatMapMany(found -> (Publisher) next.apply(found));
        }

        private static Publisher<?> proceed(MethodInvocation invocation) throws Throwable {
            return (Publisher<?>) invocation.proceed();
        }
    }
}
