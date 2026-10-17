package io.github.rmkrdev.entra.security.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * An in-process stand-in for Microsoft Entra ID and the parts of Microsoft Graph the starter uses.
 * <p>
 * It listens on a random loopback port and serves, for any tenant:
 * <ul>
 * <li>{@code GET /{tenant}/discovery/v2.0/keys}: the JWKS holding this authority's RSA signing key;</li>
 * <li>{@code GET /{tenant}/v2.0/.well-known/openid-configuration}: a minimal discovery document;</li>
 * <li>{@code POST /{tenant}/oauth2/v2.0/token}: client-credentials tokens (app-only, signed by this authority,
 * audience taken from the requested {@code scope});</li>
 * <li>{@code GET /v1.0/users/{oid}/transitiveMemberOf}: the groups registered with
 * {@link #registerGroups(String, Map)}, for group-overage tests.</li>
 * </ul>
 * Point {@code entra.security.authority-host} and {@code entra.security.graph.base-url} at {@link #baseUrl()} and
 * mint tokens with {@link #tokens(String, String)}. With {@link AutoConfigureEntraMockAuthority} all of this is
 * wired automatically. Nothing ever reaches a real tenant.
 */
public final class EntraMockAuthority implements AutoCloseable {

    private static final Pattern JWKS = Pattern.compile("^/([^/]+)/discovery(/v2\\.0)?/keys$");
    private static final Pattern DISCOVERY = Pattern.compile("^/([^/]+)/v2\\.0/\\.well-known/openid-configuration$");
    private static final Pattern TOKEN = Pattern.compile("^/([^/]+)/oauth2(/v2\\.0)?/token$");
    private static final Pattern GROUPS = Pattern.compile("^/v1\\.0/users/([^/]+)/transitiveMemberOf$");

    private static volatile EntraMockAuthority shared;

    private final ObjectMapper json = new ObjectMapper();
    private final RSAKey signingKey;
    private final RSAKey foreignKey;
    private final HttpServer server;
    private final ExecutorService executor;
    private final String baseUrl;
    private final Map<String, Map<String, String>> groupsByUser = new ConcurrentHashMap<>();
    private final AtomicInteger jwksRequests = new AtomicInteger();
    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final AtomicInteger graphRequests = new AtomicInteger();

    private EntraMockAuthority() {
        String kid = "mock-" + UUID.randomUUID();
        this.signingKey = generate(kid);
        this.foreignKey = generate(kid);
        try {
            this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        }
        catch (IOException ex) {
            throw new UncheckedIOException("Could not start the mock Entra authority", ex);
        }
        this.executor = Executors.newFixedThreadPool(4, runnable -> {
            Thread thread = new Thread(runnable, "entra-mock-authority");
            thread.setDaemon(true);
            return thread;
        });
        server.setExecutor(executor);
        server.createContext("/", this::handle);
        server.start();
        this.baseUrl = "http://" + server.getAddress().getHostString() + ":" + server.getAddress().getPort();
    }

    /**
     * Starts a new authority. Close it when done, or use {@link #shared()}.
     */
    public static EntraMockAuthority start() {
        return new EntraMockAuthority();
    }

    /**
     * The JVM-wide authority used by {@link AutoConfigureEntraMockAuthority}, started on first use and stopped at
     * JVM shutdown. Sharing one instance keeps Spring's test-context cache effective.
     */
    public static EntraMockAuthority shared() {
        EntraMockAuthority result = shared;
        if (result == null) {
            synchronized (EntraMockAuthority.class) {
                result = shared;
                if (result == null) {
                    result = new EntraMockAuthority();
                    Runtime.getRuntime().addShutdownHook(new Thread(result::close, "entra-mock-authority-stop"));
                    shared = result;
                }
            }
        }
        return result;
    }

    /** The authority host, for {@code entra.security.authority-host} and {@code entra.security.graph.base-url}. */
    public String baseUrl() {
        return baseUrl;
    }

    /** The v2 issuer of tokens for the given tenant: {@code {baseUrl}/{tenant}/v2.0}. */
    public String issuer(String tenantId) {
        return baseUrl + "/" + tenantId + "/v2.0";
    }

    /** The JWKS endpoint for the given tenant. */
    public String jwkSetUri(String tenantId) {
        return baseUrl + "/" + tenantId + "/discovery/v2.0/keys";
    }

    /** The public JWKS document served by this authority. */
    public String jwksJson() {
        return new JWKSet(signingKey.toPublicJWK()).toString();
    }

    /**
     * A token factory for an API registered in the given tenant.
     *
     * @param tenantId the API's {@code entra.security.tenant-id}
     * @param clientId the API's {@code entra.security.client-id}; tokens use it as the audience
     */
    public EntraTestTokens tokens(String tenantId, String clientId) {
        return new EntraTestTokens(this, tenantId, clientId);
    }

    /**
     * Registers the groups Microsoft Graph returns for a user, keyed by group object id with the display name as
     * value (the name may be {@code null}). Used when a token signals group overage.
     */
    public EntraMockAuthority registerGroups(String userObjectId, Map<String, String> groups) {
        groupsByUser.put(userObjectId.toLowerCase(), new LinkedHashMap<>(groups));
        return this;
    }

    /** Registers group ids (without display names) returned by Microsoft Graph for a user. */
    public EntraMockAuthority registerGroups(String userObjectId, String... groupIds) {
        Map<String, String> groups = new LinkedHashMap<>();
        for (String id : groupIds) {
            groups.put(id, null);
        }
        return registerGroups(userObjectId, groups);
    }

    /** Forgets all registered Graph groups and resets the request counters. */
    public EntraMockAuthority reset() {
        groupsByUser.clear();
        jwksRequests.set(0);
        tokenRequests.set(0);
        graphRequests.set(0);
        return this;
    }

    /** Number of JWKS requests served since start or the last {@link #reset()}. */
    public int jwksRequests() {
        return jwksRequests.get();
    }

    /** Number of token-endpoint requests served since start or the last {@link #reset()}. */
    public int tokenRequests() {
        return tokenRequests.get();
    }

    /** Number of Graph group lookups served since start or the last {@link #reset()}. */
    public int graphRequests() {
        return graphRequests.get();
    }

    RSAKey signingKey() {
        return signingKey;
    }

    RSAKey foreignKey() {
        return foreignKey;
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    // ------------------------------------------------------------------ HTTP

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            Matcher matcher;
            if ("GET".equals(method) && JWKS.matcher(path).matches()) {
                jwksRequests.incrementAndGet();
                send(exchange, 200, jwksJson());
            }
            else if ("GET".equals(method) && (matcher = DISCOVERY.matcher(path)).matches()) {
                String tenant = matcher.group(1);
                Map<String, Object> doc = new LinkedHashMap<>();
                doc.put("issuer", issuer(tenant));
                doc.put("jwks_uri", jwkSetUri(tenant));
                doc.put("token_endpoint", baseUrl + "/" + tenant + "/oauth2/v2.0/token");
                doc.put("id_token_signing_alg_values_supported", List.of("RS256"));
                send(exchange, 200, write(doc));
            }
            else if ("POST".equals(method) && (matcher = TOKEN.matcher(path)).matches()) {
                tokenRequests.incrementAndGet();
                issueToken(exchange, matcher.group(1));
            }
            else if ("GET".equals(method) && (matcher = GROUPS.matcher(path)).matches()) {
                graphRequests.incrementAndGet();
                listGroups(exchange, matcher.group(1));
            }
            else {
                send(exchange, 404, "{\"error\":\"not_found\"}");
            }
        }
    }

    private void issueToken(HttpExchange exchange, String tenant) throws IOException {
        Map<String, String> form = parseForm(exchange.getRequestBody());
        if (!"client_credentials".equals(form.get("grant_type"))) {
            send(exchange, 400, write(Map.of("error", "unsupported_grant_type")));
            return;
        }
        String scope = form.getOrDefault("scope", "");
        String audience = scope.endsWith("/.default") ? scope.substring(0, scope.length() - "/.default".length())
                : scope;
        String clientId = form.getOrDefault("client_id", EntraTestTokens.SERVICE_APP_ID);
        String token = new EntraTestTokens(this, tenant, audience).service()
                .appId(clientId)
                .audience(audience)
                .expiresIn(Duration.ofHours(1))
                .build();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token_type", "Bearer");
        body.put("expires_in", 3600);
        body.put("access_token", token);
        send(exchange, 200, write(body));
    }

    private void listGroups(HttpExchange exchange, String objectId) throws IOException {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            send(exchange, 401, write(Map.of("error", Map.of("code", "InvalidAuthenticationToken"))));
            return;
        }
        List<Map<String, Object>> value = new ArrayList<>();
        groupsByUser.getOrDefault(objectId.toLowerCase(), Map.of()).forEach((id, name) -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("@odata.type", "#microsoft.graph.group");
            item.put("id", id);
            item.put("displayName", name);
            value.add(item);
        });
        send(exchange, 200, write(Map.of("value", value)));
    }

    private static Map<String, String> parseForm(InputStream body) throws IOException {
        Map<String, String> form = new LinkedHashMap<>();
        String raw = new String(body.readAllBytes(), StandardCharsets.UTF_8);
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String key = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            form.put(key, value);
        }
        return form;
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        }
        catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static RSAKey generate(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        }
        catch (JOSEException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
