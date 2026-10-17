package io.github.rmkrdev.entra.security.test;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Points the Entra security starter of a Spring test context at the shared {@link EntraMockAuthority}.
 * <p>
 * On a {@code @SpringBootTest} (or any Spring test class) this:
 * <ul>
 * <li>sets {@code entra.security.authority-host}, {@code entra.security.jwk-set-uri} and
 * {@code entra.security.graph.base-url} to the mock authority, overriding the application's values;</li>
 * <li>registers the {@link EntraMockAuthority} bean;</li>
 * <li>registers an {@link EntraTestTokens} bean bound to the context's {@code entra.security.tenant-id} and
 * {@code entra.security.client-id} (or the first {@code entra.security.audiences} entry).</li>
 * </ul>
 *
 * <pre>{@code
 * @SpringBootTest
 * @AutoConfigureMockMvc
 * @AutoConfigureEntraMockAuthority
 * class OrderApiTest {
 *     @Autowired MockMvc mvc;
 *     @Autowired EntraTestTokens tokens;
 *
 *     @Test
 *     void readersCanList() throws Exception {
 *         mvc.perform(get("/api/orders").header("Authorization", tokens.user().groups(READERS).bearer()))
 *            .andExpect(status().isOk());
 *     }
 * }
 * }</pre>
 * Real token validation runs end to end: signature against the JWKS, issuer, audience, tenant, expiry, role
 * mapping and, for group overage, the Graph lookup.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
public @interface AutoConfigureEntraMockAuthority {
}
