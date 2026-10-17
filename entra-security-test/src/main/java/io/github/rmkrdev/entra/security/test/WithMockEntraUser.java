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
 * Runs a test as an Entra user, without a token or a JWKS.
 * <p>
 * The security context holds an {@code EntraAuthenticationToken} whose {@code EntraPrincipal} is built from the
 * attributes below. When the test has an application context with the starter's
 * {@code EntraJwtAuthenticationConverter}, the attributes go through the real role mapping
 * ({@code group-role-mappings}, {@code app-role-mappings}, scopes, default roles), so the test checks your
 * configuration too. Without one, {@link #appRoles()} become {@code ROLE_<value>}. {@link #roles()} are always
 * added as {@code ROLE_<value>}.
 *
 * <pre>{@code
 * @Test
 * @WithMockEntraUser(groups = READERS_GROUP)
 * void readersCanList() throws Exception {
 *     mvc.perform(get("/api/orders")).andExpect(status().isOk());
 * }
 * }</pre>
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockEntraUserSecurityContextFactory.class)
public @interface WithMockEntraUser {

    /** The user's {@code oid}. */
    String objectId() default EntraTestTokens.USER_OBJECT_ID;

    /** The {@code groups} claim (object ids or names). */
    String[] groups() default {};

    /** The {@code roles} claim (app roles assigned on the enterprise application). */
    String[] appRoles() default {};

    /** The {@code scp} claim. */
    String[] scopes() default { "access_as_user" };

    /** Extra role authorities, added as {@code ROLE_<value>} on top of the mapped ones. */
    String[] roles() default {};

    /** The {@code name} claim. */
    String name() default "Test User";

    /** The {@code preferred_username} claim. */
    String username() default "test.user@contoso.example";

    /** The client application ({@code azp}). */
    String appId() default EntraTestTokens.USER_CLIENT_APP_ID;

    /** The {@code tid} claim; empty means {@code entra.security.tenant-id} when available. */
    String tenantId() default "";

    /** When the security context is set up. */
    @AliasFor(annotation = WithSecurityContext.class)
    TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;
}
