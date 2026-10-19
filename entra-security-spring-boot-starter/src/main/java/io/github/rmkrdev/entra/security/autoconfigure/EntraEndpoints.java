package io.github.rmkrdev.entra.security.autoconfigure;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * The authority endpoints this API uses, resolved once at startup from {@code entra.security.authority.*} (and
 * the older top-level {@code authority-host}, {@code jwk-set-uri} and {@code issuers}), optionally completed from
 * the OIDC discovery document.
 * <p>
 * Precedence for every endpoint: the explicit {@code entra.security.authority.*} value, then the older top-level
 * property where one exists, then the value from the discovery document (when discovery is on), then the Entra
 * default built from {@code {host}/{tenant-path}}. With nothing configured the result is exactly what earlier
 * versions used.
 */
public final class EntraEndpoints {

    private static final Logger log = LoggerFactory.getLogger(EntraEndpoints.class);

    private final URI authorityHost;
    private final String tenantPath;
    private final Set<String> issuers;
    private final URI jwksUri;
    private final URI tokenEndpoint;
    private final boolean tokenEndpointCustomized;
    private final URI authorizeEndpoint;
    private final URI userinfoEndpoint;
    private final URI graphBaseUrl;
    private final URI metadataUri;
    private final Map<String, Object> metadata;

    private EntraEndpoints(Builder builder) {
        this.authorityHost = builder.authorityHost;
        this.tenantPath = builder.tenantPath;
        this.issuers = Collections.unmodifiableSet(new LinkedHashSet<>(builder.issuers));
        this.jwksUri = builder.jwksUri;
        this.tokenEndpoint = builder.tokenEndpoint;
        this.tokenEndpointCustomized = builder.tokenEndpointCustomized;
        this.authorizeEndpoint = builder.authorizeEndpoint;
        this.userinfoEndpoint = builder.userinfoEndpoint;
        this.graphBaseUrl = builder.graphBaseUrl;
        this.metadataUri = builder.metadataUri;
        this.metadata = builder.metadata == null ? Map.of() : Collections.unmodifiableMap(builder.metadata);
    }

    /**
     * Resolves the endpoints from configuration alone, without OIDC discovery.
     */
    public static EntraEndpoints of(EntraSecurityProperties properties) {
        return builder(properties).build();
    }

    /**
     * Resolves the endpoints, fetching the OIDC discovery document with {@code restClient} when
     * {@code entra.security.authority.discovery.enabled=true} or {@code authority.metadata-uri} is set.
     *
     * @throws IllegalStateException when discovery is required and the document cannot be fetched or is invalid
     */
    public static EntraEndpoints resolve(EntraSecurityProperties properties, RestClient restClient) {
        if (!properties.isDiscoveryActive()) {
            return of(properties);
        }
        URI metadataUri = properties.resolveMetadataUri();
        JsonNode document;
        try {
            document = fetch(restClient, metadataUri);
            validateDocument(properties, metadataUri, document);
        }
        catch (RuntimeException ex) {
            String message = "OIDC discovery from " + metadataUri + " failed: " + ex.getMessage()
                    + ". Check entra.security.authority.metadata-uri (or host and tenant-path) and network egress";
            if (properties.getAuthority().getDiscovery().isRequired()) {
                throw new IllegalStateException(message, ex);
            }
            log.warn("{}; using the configured and default endpoints instead", message);
            return of(properties);
        }
        return builder(properties).discovered(properties, metadataUri, document).build();
    }

    private static JsonNode fetch(RestClient restClient, URI metadataUri) {
        try {
            JsonNode document = restClient.get().uri(metadataUri).accept(MediaType.APPLICATION_JSON).retrieve()
                    .body(JsonNode.class);
            if (document == null || !document.isObject()) {
                throw new IllegalStateException("the response is not a JSON object");
            }
            return document;
        }
        catch (RestClientException ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }

    private static void validateDocument(EntraSecurityProperties properties, URI metadataUri, JsonNode document) {
        if (!document.hasNonNull("issuer") || document.get("issuer").asText().isBlank()) {
            throw new IllegalStateException("the document has no issuer");
        }
        if (!document.hasNonNull("jwks_uri") && properties.getAuthority().getJwksUri() == null
                && properties.getJwkSetUri() == null) {
            throw new IllegalStateException("the document has no jwks_uri");
        }
        boolean allowHttp = properties.getAuthority().isAllowHttp();
        for (String field : new String[] { "jwks_uri", "token_endpoint", "authorization_endpoint",
                "userinfo_endpoint", "introspection_endpoint" }) {
            if (document.hasNonNull(field)) {
                URI uri;
                try {
                    uri = URI.create(document.get(field).asText());
                }
                catch (IllegalArgumentException ex) {
                    throw new IllegalStateException(field + " is not a valid URL", ex);
                }
                String problem = EntraSecurityProperties.Authority.uriProblem(uri, allowHttp);
                if (problem != null) {
                    throw new IllegalStateException(field + " " + problem);
                }
            }
        }
    }

    private static Builder builder(EntraSecurityProperties properties) {
        EntraSecurityProperties.Authority authority = properties.getAuthority();
        Builder builder = new Builder();
        builder.authorityHost = properties.resolveAuthorityHost();
        builder.tenantPath = properties.resolveTenantPath();
        builder.issuers = properties.resolveIssuers();
        builder.jwksUri = properties.resolveJwkSetUri();
        builder.tokenEndpoint = properties.resolveTokenEndpoint();
        builder.tokenEndpointCustomized = authority.getTokenEndpoint() != null;
        builder.authorizeEndpoint = properties.resolveAuthorizeEndpoint();
        builder.userinfoEndpoint = properties.resolveUserinfoEndpoint();
        builder.graphBaseUrl = properties.resolveGraphBaseUrl();
        return builder;
    }

    /** The authority host, for example {@code https://login.microsoftonline.com}. */
    public URI authorityHost() {
        return authorityHost;
    }

    /** The path after the host, by default the tenant id. */
    public String tenantPath() {
        return tenantPath;
    }

    /** The accepted {@code iss} values. */
    public Set<String> issuers() {
        return issuers;
    }

    /** The JWKS endpoint. */
    public URI jwksUri() {
        return jwksUri;
    }

    /** The token endpoint of this API's tenant. */
    public URI tokenEndpoint() {
        return tokenEndpoint;
    }

    /**
     * Whether the token endpoint was configured or discovered rather than derived from the host, in which case
     * it is used as is, also for workload identity.
     */
    public boolean isTokenEndpointCustomized() {
        return tokenEndpointCustomized;
    }

    /** The authorize endpoint. The starter does not call it. */
    public URI authorizeEndpoint() {
        return authorizeEndpoint;
    }

    /** The OIDC userinfo endpoint. */
    public URI userinfoEndpoint() {
        return userinfoEndpoint;
    }

    /** The Microsoft Graph base URL. */
    public URI graphBaseUrl() {
        return graphBaseUrl;
    }

    /** The discovery document URL, or {@code null} when discovery is off. */
    public URI metadataUri() {
        return metadataUri;
    }

    /** Whether the endpoints were completed from an OIDC discovery document. */
    public boolean isDiscovered() {
        return metadataUri != null;
    }

    /**
     * A string field of the discovery document, such as {@code introspection_endpoint}, or {@code null}.
     */
    public String metadata(String name) {
        Object value = metadata.get(name);
        return value == null ? null : value.toString();
    }

    @Override
    public String toString() {
        return "EntraEndpoints{authorityHost=" + authorityHost + ", tenantPath=" + tenantPath + ", issuers=" + issuers
                + ", jwksUri=" + jwksUri + ", tokenEndpoint=" + tokenEndpoint + ", graphBaseUrl=" + graphBaseUrl
                + (metadataUri != null ? ", metadataUri=" + metadataUri : "") + "}";
    }

    private static final class Builder {

        private URI authorityHost;
        private String tenantPath;
        private Set<String> issuers;
        private URI jwksUri;
        private URI tokenEndpoint;
        private boolean tokenEndpointCustomized;
        private URI authorizeEndpoint;
        private URI userinfoEndpoint;
        private URI graphBaseUrl;
        private URI metadataUri;
        private Map<String, Object> metadata;

        Builder discovered(EntraSecurityProperties properties, URI documentUri, JsonNode document) {
            EntraSecurityProperties.Authority authority = properties.getAuthority();
            this.metadataUri = documentUri;
            this.metadata = new java.util.LinkedHashMap<>();
            document.properties().forEach(field -> {
                if (field.getValue().isValueNode()) {
                    metadata.put(field.getKey(), field.getValue().asText());
                }
            });
            if (authority.getIssuers().isEmpty() && properties.getIssuers().isEmpty()) {
                String issuer = document.get("issuer").asText();
                // Entra's multi-tenant documents carry a {tenantid} placeholder.
                this.issuers = Set.of(issuer.replace("{tenantid}", String.valueOf(properties.getTenantId())));
            }
            if (authority.getJwksUri() == null && properties.getJwkSetUri() == null && document.hasNonNull("jwks_uri")) {
                this.jwksUri = URI.create(document.get("jwks_uri").asText());
            }
            if (authority.getTokenEndpoint() == null && document.hasNonNull("token_endpoint")) {
                this.tokenEndpoint = URI.create(document.get("token_endpoint").asText());
                this.tokenEndpointCustomized = true;
            }
            if (authority.getAuthorizeEndpoint() == null && document.hasNonNull("authorization_endpoint")) {
                this.authorizeEndpoint = URI.create(document.get("authorization_endpoint").asText());
            }
            if (authority.getUserinfoEndpoint() == null && document.hasNonNull("userinfo_endpoint")) {
                this.userinfoEndpoint = URI.create(document.get("userinfo_endpoint").asText());
            }
            return this;
        }

        EntraEndpoints build() {
            return new EntraEndpoints(this);
        }
    }
}
