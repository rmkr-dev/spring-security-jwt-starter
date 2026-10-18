package io.github.rmkrdev.entra.security;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.Import;

/**
 * Explicitly opts a service into Entra security.
 * <p>
 * The starter's auto-configuration already secures the application. Adding this annotation also:
 * <ul>
 * <li>enables method security ({@code @Secured}, {@code @PreAuthorize}, {@code @RolesAllowed}) even if
 * {@code entra.security.method-security.enabled=false}. In a WebFlux application it enables
 * {@code @EnableReactiveMethodSecurity} instead, with {@code @Secured} and {@code @PreAuthorize} (and the
 * other pre/post annotations) on methods returning {@code Mono} or {@code Flux};</li>
 * <li>preloads the security context at startup: the tenant signing keys (JWKS) are fetched eagerly so the
 * first request does not pay for it, and the effective configuration is logged;</li>
 * <li>optionally fails startup when the signing keys cannot be loaded ({@link #failOnJwksError()}).</li>
 * </ul>
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import({ EntraMethodSecuritySelector.class, EntraSecurityPreloadConfiguration.class })
public @interface EnableEntraSecurity {

    /**
     * Whether to fetch the tenant JWKS at startup.
     */
    boolean preloadJwks() default true;

    /**
     * Whether startup fails when the JWKS cannot be fetched. When {@code false}, a warning is logged and
     * keys are fetched on the first request instead.
     */
    boolean failOnJwksError() default false;

    /**
     * Advice mode for method security, as on {@code @EnableMethodSecurity}. WebFlux applications always use
     * proxies.
     */
    AdviceMode mode() default AdviceMode.PROXY;

    /**
     * Whether to force class-based (CGLIB) proxies, as on {@code @EnableMethodSecurity}.
     */
    boolean proxyTargetClass() default false;
}
