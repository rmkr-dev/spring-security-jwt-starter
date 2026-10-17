package io.github.rmkrdev.entra.security.test;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

/**
 * Runs a test as a calling service (an app-only, client-credentials token), without a token or a JWKS.
 * <p>
 * With the starter's {@code EntraJwtAuthenticationConverter} in the context, {@link #appRoles()} and
 * {@link #appId()} go through {@code app-role-mappings}, {@code client-role-mappings} and the client allow-list;
 * a client rejected by {@code service.require-known-client} fails the test setup. Without one,
 * {@link #appRoles()} become {@code ROLE_<value>}. {@link #roles()} are always added as {@code ROLE_<value>}.
 *
 * <pre>{@code
 * @Test
 * @WithMockEntraService(appRoles = "Orders.Sync")
 * void peersCanSync() throws Exception {
 *     mvc.perform(post("/internal/orders/sync")).andExpect(status().isOk());
 * }
 * }</pre>
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockEntraServiceSecurityContextFactory.class)
public @interface WithMockEntraService {

    /** The calling application id ({@code azp}). */
    String appId() default EntraTestTokens.SERVICE_APP_ID;

    /** The calling service principal's {@code oid}. */
    String objectId() default EntraTestTokens.SERVICE_OBJECT_ID;

    /** The {@code roles} claim: app roles granted to the calling application. */
    String[] appRoles() default {};

    /** Extra role authorities, added as {@code ROLE_<value>} on top of the mapped ones. */
    String[] roles() default {};

    /** The {@code tid} claim; empty means {@code entra.security.tenant-id} when available. */
    String tenantId() default "";

    /** When the security context is set up. */
    @AliasFor(annotation = WithSecurityContext.class)
    TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;
}
