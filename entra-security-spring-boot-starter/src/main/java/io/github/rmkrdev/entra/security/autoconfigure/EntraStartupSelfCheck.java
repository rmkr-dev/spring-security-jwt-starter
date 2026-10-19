package io.github.rmkrdev.entra.security.autoconfigure;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.Credential;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.CredentialType;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.OutboundClient;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.ValidationMode;

/**
 * A thin startup self-check ({@code entra.security.self-check.mode=warn|fail|off}): tenant and client ids are
 * GUIDs, an audience is configured, the JWKS (or the introspection endpoint) answers, and a credential is set
 * when outbound clients exist. {@code warn} logs each problem, {@code fail} stops the application.
 */
public class EntraStartupSelfCheck implements SmartInitializingSingleton {

    /** What to do with problems. */
    public enum Mode {
        /** Log a warning per problem (default). */
        WARN,
        /** Fail startup when there is a problem. */
        FAIL,
        /** Skip the check. */
        OFF
    }

    private static final Logger log = LoggerFactory.getLogger(EntraStartupSelfCheck.class);
    private static final Pattern GUID = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private final EntraSecurityProperties properties;
    private final ObjectProvider<EntraEndpoints> endpoints;
    private final ObjectProvider<JWKSource<SecurityContext>> jwkSource;
    private volatile List<String> problems = List.of();

    public EntraStartupSelfCheck(EntraSecurityProperties properties, ObjectProvider<EntraEndpoints> endpoints,
            ObjectProvider<JWKSource<SecurityContext>> jwkSource) {
        this.properties = properties;
        this.endpoints = endpoints;
        this.jwkSource = jwkSource;
    }

    @Override
    public void afterSingletonsInstantiated() {
        Mode mode = properties.getSelfCheck().getMode();
        if (mode == Mode.OFF) {
            return;
        }
        List<String> found = check();
        this.problems = List.copyOf(found);
        if (found.isEmpty()) {
            log.info("Entra startup self-check passed");
            return;
        }
        if (mode == Mode.FAIL) {
            throw new IllegalStateException("Entra startup self-check failed (entra.security.self-check.mode=fail): "
                    + String.join("; ", found));
        }
        found.forEach(problem -> log.warn("Entra startup self-check: {}", problem));
    }

    /** The problems found by the last run. */
    public List<String> getProblems() {
        return problems;
    }

    List<String> check() {
        List<String> found = new ArrayList<>();
        guid(found, "entra.security.tenant-id", properties.getTenantId());
        guid(found, "entra.security.client-id", properties.getClientId());
        properties.getOutbound().getClients().forEach((name, client) -> {
            if (client.getCredential().getClientId() != null) {
                guid(found, "entra.security.outbound.clients." + name + ".credential.client-id",
                        client.getCredential().getClientId());
            }
        });
        boolean noAudience = properties.getAudiences().stream().allMatch(EntraStartupSelfCheck::blank)
                && blank(properties.getClientId());
        if (noAudience) {
            found.add("no audience: set entra.security.client-id or entra.security.audiences");
        }
        reachability(found);
        credentials(found);
        return found;
    }

    private static void guid(List<String> found, String property, String value) {
        if (value == null || value.isBlank()) {
            found.add(property + " is not set");
        }
        else if (!GUID.matcher(value.trim()).matches()) {
            found.add(property + "='" + value + "' is not a GUID");
        }
    }

    private void reachability(List<String> found) {
        ValidationMode mode = properties.getValidation().getMode();
        EntraEndpoints resolved = endpoints.getIfAvailable();
        if (mode != ValidationMode.INTROSPECTION) {
            JWKSource<SecurityContext> source = jwkSource.getIfAvailable();
            if (source != null) {
                try {
                    if (source.get(new JWKSelector(new JWKMatcher.Builder().build()), null).isEmpty()) {
                        found.add("the JWKS at " + jwksUri(resolved) + " has no keys");
                    }
                }
                catch (Exception ex) {
                    found.add("the JWKS at " + jwksUri(resolved) + " is not reachable: " + ex.getMessage());
                }
            }
        }
        if (mode != ValidationMode.JWKS && resolved != null) {
            URI uri;
            try {
                uri = EntraValidation.introspectionUri(properties, resolved);
            }
            catch (RuntimeException ex) {
                found.add(ex.getMessage());
                return;
            }
            String problem = reachable(uri, properties.getHttp().getConnectTimeout(),
                    properties.getHttp().getReadTimeout());
            if (problem != null) {
                found.add("the introspection endpoint " + uri + " is not reachable: " + problem);
            }
        }
    }

    private static Object jwksUri(EntraEndpoints resolved) {
        return resolved == null ? "(unresolved)" : resolved.jwksUri();
    }

    /** {@code null} when the endpoint answers with any HTTP status, otherwise why it did not. */
    static String reachable(URI uri, Duration connectTimeout, Duration readTimeout) {
        try {
            HttpClient client = EntraTokenProviders.pooledHttpClient(connectTimeout);
            client.send(HttpRequest.newBuilder(uri).timeout(readTimeout)
                    .method("HEAD", HttpRequest.BodyPublishers.noBody()).build(),
                    HttpResponse.BodyHandlers.discarding());
            return null;
        }
        catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return "interrupted";
        }
        catch (Exception ex) {
            return ex.getClass().getSimpleName() + (ex.getMessage() == null ? "" : ": " + ex.getMessage());
        }
    }

    private void credentials(List<String> found) {
        Map<String, OutboundClient> clients = properties.getOutbound().getClients();
        if (clients.isEmpty()) {
            return;
        }
        for (Map.Entry<String, OutboundClient> entry : clients.entrySet()) {
            Credential own = entry.getValue().getCredential();
            Credential effective = own.getType() != CredentialType.NONE ? own : properties.getCredential();
            String problem = credentialProblem(effective);
            if (problem != null) {
                found.add("outbound client '" + entry.getKey() + "': " + problem);
            }
        }
    }

    private static String credentialProblem(Credential credential) {
        switch (credential.getType()) {
            case NONE:
                return "no credential (set entra.security.credential.type or the client's credential.type)";
            case CLIENT_SECRET:
                return blank(credential.getClientSecret()) ? "credential.type=client-secret but client-secret is empty"
                        : null;
            case CERTIFICATE:
                return blank(credential.getCertificatePath()) && blank(credential.getKeyVault().getCertificateName())
                        ? "credential.type=certificate but no certificate-path or key-vault certificate-name" : null;
            default:
                return null;
        }
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
