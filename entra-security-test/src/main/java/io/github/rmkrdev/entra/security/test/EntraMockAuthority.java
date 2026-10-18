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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
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
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
 * audience taken from the requested {@code scope}), and on-behalf-of tokens
 * ({@code grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer}): the user assertion must be a delegated token
 * signed by this authority, unexpired, and issued to the requesting {@code client_id}; the answer is a delegated
 * token for the same user with the requested scopes. {@link #requireConsent(String)} and
 * {@link #requireInteraction(String, String)} make it answer the way Entra does when consent or MFA is
 * missing;</li>
 * <li>{@code GET /v1.0/users/{oid}/transitiveMemberOf}: the groups registered with
 * {@link #registerGroups(String, Map)}, for group-overage tests;</li>
 * <li>{@code GET /v1.0/}: the Graph service root used by the {@code entraGraph} health indicator.
 * Requires a {@code Bearer} token and is not counted by {@link #graphRequests()}.</li>
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

    private static final String JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static final java.util.Set<String> SECRET_PARAMETERS = java.util.Set.of("assertion", "client_secret",
            "client_assertion");

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
    private final AtomicInteger onBehalfOfRequests = new AtomicInteger();
    private final Map<String, Boolean> consentRequired = new ConcurrentHashMap<>();
    private final Map<String, String> interactionRequired = new ConcurrentHashMap<>();
    private final List<Map<String, String>> onBehalfOfForms = new java.util.concurrent.CopyOnWriteArrayList<>();
    private volatile Duration onBehalfOfTokenLifetime = Duration.ofHours(1);

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

    /**
     * Makes on-behalf-of requests for a scope (such as {@code api://orders/Orders.Read}) or a whole resource
     * (such as {@code api://orders}) fail like Entra does when the user has not consented: HTTP 400,
     * {@code invalid_grant}, {@code AADSTS65001}, {@code suberror=consent_required}.
     */
    public EntraMockAuthority requireConsent(String scopeOrResource) {
        consentRequired.put(scopeOrResource, Boolean.TRUE);
        return this;
    }

    /**
     * Makes on-behalf-of requests for a scope or resource fail like Entra does when Conditional Access needs
     * MFA: HTTP 400, {@code interaction_required}, {@code AADSTS50076} and the given claims challenge.
     *
     * @param claims the claims challenge JSON, or {@code null} for a default one
     */
    public EntraMockAuthority requireInteraction(String scopeOrResource, String claims) {
        interactionRequired.put(scopeOrResource, claims != null ? claims
                : "{\"access_token\":{\"capolids\":{\"essential\":true,\"values\":[\"mock-mfa-policy\"]}}}");
        return this;
    }

    /** Lifetime of on-behalf-of tokens ({@code expires_in}); one hour by default. */
    public EntraMockAuthority onBehalfOfTokenLifetime(Duration lifetime) {
        this.onBehalfOfTokenLifetime = lifetime;
        return this;
    }

    /** Forgets registered Graph groups, consent and interaction requirements, and resets the counters. */
    public EntraMockAuthority reset() {
        groupsByUser.clear();
        consentRequired.clear();
        interactionRequired.clear();
        onBehalfOfForms.clear();
        onBehalfOfTokenLifetime = Duration.ofHours(1);
        jwksRequests.set(0);
        tokenRequests.set(0);
        graphRequests.set(0);
        onBehalfOfRequests.set(0);
        return this;
    }

    /** Number of on-behalf-of token requests (successful or not) since start or the last {@link #reset()}. */
    public int onBehalfOfRequests() {
        return onBehalfOfRequests.get();
    }

    /**
     * The form parameters of the on-behalf-of requests received, oldest first, with {@code assertion},
     * {@code client_secret} and {@code client_assertion} values replaced by {@code ****}.
     */
    public List<Map<String, String>> onBehalfOfRequestForms() {
        return List.copyOf(onBehalfOfForms);
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
            else if ("GET".equals(method) && ("/v1.0".equals(path) || "/v1.0/".equals(path))) {
                graphServiceRoot(exchange);
            }
            else {
                send(exchange, 404, "{\"error\":\"not_found\"}");
            }
        }
    }

    private void issueToken(HttpExchange exchange, String tenant) throws IOException {
        Map<String, String> form = parseForm(exchange.getRequestBody());
        if (JWT_BEARER.equals(form.get("grant_type"))) {
            onBehalfOf(exchange, tenant, form);
            return;
        }
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

    private void onBehalfOf(HttpExchange exchange, String tenant, Map<String, String> form) throws IOException {
        onBehalfOfRequests.incrementAndGet();
        Map<String, String> recorded = new LinkedHashMap<>(form);
        recorded.replaceAll((key, value) -> SECRET_PARAMETERS.contains(key) ? "****" : value);
        onBehalfOfForms.add(Collections.unmodifiableMap(recorded));

        String clientId = form.get("client_id");
        String scope = form.getOrDefault("scope", "").trim();
        if (!"on_behalf_of".equals(form.get("requested_token_use"))) {
            sendError(exchange, 400, "invalid_request", 900144, "AADSTS900144: The request body must contain the "
                    + "following parameter: 'requested_token_use'.", null, null);
            return;
        }
        if (clientId == null || scope.isEmpty() || form.get("assertion") == null) {
            sendError(exchange, 400, "invalid_request", 900144, "AADSTS900144: The request body must contain "
                    + "client_id, scope and assertion.", null, null);
            return;
        }
        if (form.get("client_secret") == null && form.get("client_assertion") == null) {
            sendError(exchange, 401, "invalid_client", 7000218, "AADSTS7000218: The request body must contain the "
                    + "following parameter: 'client_assertion' or 'client_secret'.", null, null);
            return;
        }
        JWTClaimsSet assertion;
        try {
            SignedJWT jwt = SignedJWT.parse(form.get("assertion"));
            if (!jwt.verify(new RSASSAVerifier(signingKey.toRSAPublicKey()))) {
                throw new IllegalArgumentException("bad signature");
            }
            assertion = jwt.getJWTClaimsSet();
        }
        catch (java.text.ParseException | JOSEException | IllegalArgumentException ex) {
            sendError(exchange, 400, "invalid_grant", 50013, "AADSTS50013: Assertion failed signature validation.",
                    null, null);
            return;
        }
        if (assertion.getExpirationTime() == null || assertion.getExpirationTime().toInstant().isBefore(Instant.now())) {
            sendError(exchange, 400, "invalid_grant", 500133, "AADSTS500133: Assertion is not within its valid "
                    + "time range.", null, null);
            return;
        }
        List<String> audience = assertion.getAudience();
        if (audience == null || !(audience.contains(clientId) || audience.contains("api://" + clientId))) {
            sendError(exchange, 400, "invalid_grant", 50013, "AADSTS50013: Assertion audience does not match the "
                    + "Client app presenting the assertion.", null, null);
            return;
        }
        Object scp = assertion.getClaim("scp");
        if ("app".equals(assertion.getClaim("idtyp")) || scp == null || scp.toString().isBlank()) {
            sendError(exchange, 400, "invalid_grant", 50013, "AADSTS50013: The assertion is not a delegated user "
                    + "token.", null, null);
            return;
        }
        List<String> scopes = List.of(scope.split("\\s+"));
        String resource = resourceOf(scopes.get(0));
        for (String requested : scopes) {
            if (consentRequired.containsKey(requested) || consentRequired.containsKey(resourceOf(requested))) {
                sendError(exchange, 400, "invalid_grant", 65001, "AADSTS65001: The user or administrator has not "
                        + "consented to use the application with ID '" + clientId + "'. Send an interactive "
                        + "authorization request for this user and resource.", "consent_required", null);
                return;
            }
            String claims = interactionRequired.containsKey(requested) ? interactionRequired.get(requested)
                    : interactionRequired.get(resourceOf(requested));
            if (claims != null) {
                sendError(exchange, 400, "interaction_required", 50076, "AADSTS50076: Due to a configuration "
                        + "change made by your administrator, or because you moved to a new location, you must use "
                        + "multi-factor authentication to access '" + resource + "'.", "basic_action", claims);
                return;
            }
        }
        List<String> grantedScopes = scopes.stream().map(EntraMockAuthority::scopeName)
                .filter(name -> !".default".equals(name)).toList();
        Duration lifetime = onBehalfOfTokenLifetime;
        EntraTestTokens.TokenBuilder builder = new EntraTestTokens(this, tenant, resource).user()
                .appId(clientId)
                .audience(resource)
                .scopes(grantedScopes.isEmpty() ? new String[] { "user_impersonation" }
                        : grantedScopes.toArray(String[]::new))
                .expiresIn(lifetime);
        for (String claim : List.of("oid", "sub", "name", "preferred_username", "upn")) {
            builder.claim(claim, assertion.getClaim(claim));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token_type", "Bearer");
        body.put("scope", String.join(" ", scopes));
        body.put("expires_in", lifetime.toSeconds());
        body.put("ext_expires_in", lifetime.toSeconds());
        body.put("access_token", builder.build());
        send(exchange, 200, write(body));
    }

    private static String resourceOf(String scope) {
        int slash = scope.lastIndexOf('/');
        return slash > 0 && !scope.endsWith("//") ? scope.substring(0, slash) : scope;
    }

    private static String scopeName(String scope) {
        int slash = scope.lastIndexOf('/');
        return slash >= 0 ? scope.substring(slash + 1) : scope;
    }

    private void sendError(HttpExchange exchange, int status, String error, int code, String description,
            String suberror, String claims) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description + "\r\nTrace ID: " + UUID.randomUUID());
        body.put("error_codes", List.of(code));
        if (suberror != null) {
            body.put("suberror", suberror);
        }
        if (claims != null) {
            body.put("claims", claims);
        }
        send(exchange, status, write(body));
    }

    private void graphServiceRoot(HttpExchange exchange) throws IOException {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")
                || authorization.length() <= "Bearer ".length()) {
            send(exchange, 401, "{\"error\":\"unauthorized\"}");
            return;
        }
        send(exchange, 200, "{\"@odata.context\":\"https://graph.microsoft.com/v1.0/$metadata\"}");
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
