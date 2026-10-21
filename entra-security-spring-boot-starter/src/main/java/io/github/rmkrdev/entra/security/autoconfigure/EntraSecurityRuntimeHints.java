package io.github.rmkrdev.entra.security.autoconfigure;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;

/**
 * Reflection and resource hints for a native image. Spring Boot's AOT processing picks this up from
 * {@link org.springframework.context.annotation.ImportRuntimeHints} on the auto-configuration.
 */
public final class EntraSecurityRuntimeHints implements RuntimeHintsRegistrar {

    private static final MemberCategory[] REFLECTION = {
            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
            MemberCategory.INVOKE_PUBLIC_METHODS };

    @Override
    public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
        hints.resources().registerPattern("META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports");
        hints.resources().registerPattern("META-INF/spring-autoconfigure-metadata.properties");
        hints.resources().registerPattern("META-INF/spring-configuration-metadata.json");
        hints.resources().registerPattern("META-INF/services/com.nimbusds.*");
        register(hints, classLoader, EntraSecurityAutoConfiguration.class.getName());
        register(hints, classLoader, EntraReactiveSecurityAutoConfiguration.class.getName());
        register(hints, classLoader, EntraOutboundAutoConfiguration.class.getName());
        register(hints, classLoader, "io.github.rmkrdev.entra.security.autoconfigure.health.EntraHealthAutoConfiguration");
        register(hints, classLoader, "io.github.rmkrdev.entra.security.autoconfigure.health.EntraJwksHealthIndicator");
        register(hints, classLoader, "io.github.rmkrdev.entra.security.autoconfigure.health.EntraJwksReactiveHealthIndicator");
        register(hints, classLoader, "io.github.rmkrdev.entra.security.autoconfigure.health.EntraGraphHealthIndicator");
        register(hints, classLoader, "io.github.rmkrdev.entra.security.autoconfigure.health.EntraGraphReactiveHealthIndicator");
        register(hints, classLoader, "io.github.rmkrdev.entra.security.autoconfigure.metrics.EntraMetricsAutoConfiguration");
        register(hints, classLoader, "io.github.rmkrdev.entra.security.autoconfigure.metrics.EntraMonitoringAutoConfiguration");
        register(hints, classLoader, "io.github.rmkrdev.entra.security.autoconfigure.keyvault.EntraKeyVaultAutoConfiguration");
        register(hints, classLoader, "com.nimbusds.jose.jwk.RSAKey");
        register(hints, classLoader, "com.nimbusds.jose.jwk.JWKSet");
        register(hints, classLoader, "com.nimbusds.jose.crypto.RSASSAVerifier");
        register(hints, classLoader, "com.nimbusds.jose.proc.DefaultJWTProcessor");
        register(hints, classLoader, "java.net.http.HttpClient");
        register(hints, classLoader, "tools.jackson.databind.json.JsonMapper");
    }

    private static void register(RuntimeHints hints, ClassLoader classLoader, String name) {
        try {
            Class<?> type = Class.forName(name, false, classLoader);
            hints.reflection().registerType(type, REFLECTION);
        }
        catch (ClassNotFoundException ex) {
            // Optional dependency (Nimbus is required; a future split module may be absent).
        }
    }
}
