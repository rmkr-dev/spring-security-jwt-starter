package io.github.rmkrdev.entra.security.autoconfigure;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.validation.annotation.Validated;

import io.github.rmkrdev.entra.security.core.authority.CompactRoleMappings;
import io.github.rmkrdev.entra.security.core.authority.CompactRoleMappings.KeyType;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Configuration for the Entra ID security starter, bound from {@code entra.security.*}.
 * <p>
 * Works with {@code application.yaml}, a mounted Kubernetes ConfigMap, environment variables
 * ({@code ENTRA_SECURITY_TENANTID}, {@code ENTRA_SECURITY_CLIENTID}, ...) and
 * {@code SPRING_APPLICATION_JSON}.
 */
@Validated
@ConfigurationProperties(prefix = EntraSecurityProperties.PREFIX)
public class EntraSecurityProperties implements Validator {

    public static final String PREFIX = "entra.security";

    static final Pattern GUID = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Set<String> MULTI_TENANT_AUTHORITIES = Set.of("common", "organizations", "consumers");

    /** Whether the starter is active. */
    private boolean enabled = true;

    /** Directory (tenant) ID of your Microsoft Entra tenant (a GUID). */
    @NotBlank(message = "must be set to your Microsoft Entra directory (tenant) ID "
            + "(entra.security.tenant-id or env ENTRA_SECURITY_TENANTID)")
    private String tenantId;

    /** Application (client) ID of this API's app registration. */
    @NotBlank(message = "must be set to the application (client) ID of this API's app registration "
            + "(entra.security.client-id or env ENTRA_SECURITY_CLIENTID)")
    private String clientId;

    /** Entra authority host. Change it for sovereign clouds, for example https://login.microsoftonline.us. */
    @NotNull
    private URI authorityHost = URI.create("https://login.microsoftonline.com");

    /** JWKS endpoint. Defaults to {authority-host}/{tenant-id}/discovery/v2.0/keys. */
    private URI jwkSetUri;

    /** Accepted token audiences. Defaults to api://{client-id} and {client-id}. */
    private List<String> audiences = new ArrayList<>();

    /** Accepted token issuers. Defaults to the tenant's v1 (sts.windows.net) and v2 issuers. */
    private List<String> issuers = new ArrayList<>();

    /** Tolerated clock skew when checking exp and nbf. */
    @NotNull
    private Duration clockSkew = Duration.ofSeconds(60);

    /** Whether the tid claim must equal tenant-id. */
    private boolean requireTenantMatch = true;

    /** Ant-style paths that are reachable without a token. */
    private List<String> publicPaths = new ArrayList<>(List.of("/actuator/health", "/actuator/health/**",
            "/actuator/info"));

    /** Group object id (or group name, when the groups claim emits names) to roles. */
    private Map<String, List<String>> groupRoleMappings = new LinkedHashMap<>();

    /** App role value (the roles claim) to roles. Unmapped app roles become ROLE_{value} unless disabled. */
    private Map<String, List<String>> appRoleMappings = new LinkedHashMap<>();

    /** Calling client id (azp/appid) to roles. Also the allow-list when service.require-known-client is true. */
    private Map<String, List<String>> clientRoleMappings = new LinkedHashMap<>();

    /**
     * Group mappings on one line, merged with group-role-mappings: {@code <group>=<ROLE>[|<ROLE>...]} entries
     * separated by ';' or ','. Suits environment variables (ENTRA_SECURITY_GROUPROLEMAPPINGSCOMPACT) and
     * ConfigMap scalars.
     */
    private String groupRoleMappingsCompact;

    /** App role mappings on one line, merged with app-role-mappings: {@code <app-role>=<ROLE>[|<ROLE>...];...}. */
    private String appRoleMappingsCompact;

    /**
     * Client mappings on one line, merged with client-role-mappings: {@code <client-id>=<ROLE>[|<ROLE>...];...}.
     * Client ids must be GUIDs.
     */
    private String clientRoleMappingsCompact;

    @Valid
    private final User user = new User();

    @Valid
    private final Service service = new Service();

    @Valid
    private final Graph graph = new Graph();

    /** This API's own credential, used for Microsoft Graph and as the default for outbound clients. */
    @Valid
    private final Credential credential = new Credential();

    @Valid
    private final Outbound outbound = new Outbound();

    @Valid
    private final Cache cache = new Cache();

    @Valid
    private final Http http = new Http();

    private final MethodSecurity methodSecurity = new MethodSecurity();

    private final Logging logging = new Logging();

    // ---------------------------------------------------------------- derived values

    /** The effective issuers: the configured ones, or the tenant's v1 and v2 issuers. */
    public Set<String> resolveIssuers() {
        if (!issuers.isEmpty()) {
            return new LinkedHashSet<>(issuers);
        }
        Set<String> result = new LinkedHashSet<>();
        result.add(trimSlash(authorityHost.toString()) + "/" + tenantId + "/v2.0");
        result.add("https://sts.windows.net/" + tenantId + "/");
        return result;
    }

    /** The effective audiences: the configured ones, or api://{client-id} and {client-id}. */
    public Set<String> resolveAudiences() {
        if (!audiences.isEmpty()) {
            return new LinkedHashSet<>(audiences);
        }
        return new LinkedHashSet<>(List.of("api://" + clientId, clientId));
    }

    /** The effective JWKS endpoint. */
    public URI resolveJwkSetUri() {
        if (jwkSetUri != null) {
            return jwkSetUri;
        }
        return URI.create(trimSlash(authorityHost.toString()) + "/" + tenantId + "/discovery/v2.0/keys");
    }

    /**
     * The {@code tid} every token must carry, or {@code null} when the check is off or the tenant is not
     * a GUID (domain tenants are covered by the explicit issuers instead).
     */
    public String resolveRequiredTenantId() {
        return requireTenantMatch && tenantId != null && GUID.matcher(tenantId).matches() ? tenantId : null;
    }

    /** Group mappings from group-role-mappings and group-role-mappings-compact combined. */
    public Map<String, List<String>> resolveGroupRoleMappings() {
        return CompactRoleMappings.merge(groupRoleMappings, CompactRoleMappings.parse(
                PREFIX + ".group-role-mappings-compact", groupRoleMappingsCompact, KeyType.GROUP));
    }

    /** App role mappings from app-role-mappings and app-role-mappings-compact combined. */
    public Map<String, List<String>> resolveAppRoleMappings() {
        return CompactRoleMappings.merge(appRoleMappings, CompactRoleMappings.parse(
                PREFIX + ".app-role-mappings-compact", appRoleMappingsCompact, KeyType.APP_ROLE));
    }

    /** Client mappings (and allow-list) from client-role-mappings and client-role-mappings-compact combined. */
    public Map<String, List<String>> resolveClientRoleMappings() {
        return CompactRoleMappings.merge(clientRoleMappings, CompactRoleMappings.parse(
                PREFIX + ".client-role-mappings-compact", clientRoleMappingsCompact, KeyType.CLIENT_ID));
    }

    // ---------------------------------------------------------------- cross-field validation

    @Override
    public boolean supports(Class<?> type) {
        return EntraSecurityProperties.class.isAssignableFrom(type);
    }

    /**
     * Checks the compact role mappings, reporting the entry that is wrong and why. Called by Spring Boot
     * when the properties are bound, alongside the bean validation constraints.
     */
    @Override
    public void validate(Object target, Errors errors) {
        EntraSecurityProperties properties = (EntraSecurityProperties) target;
        validateCompact(errors, "groupRoleMappingsCompact", properties::resolveGroupRoleMappings);
        validateCompact(errors, "appRoleMappingsCompact", properties::resolveAppRoleMappings);
        validateCompact(errors, "clientRoleMappingsCompact", properties::resolveClientRoleMappings);
    }

    private static void validateCompact(Errors errors, String field, Runnable resolve) {
        try {
            resolve.run();
        }
        catch (IllegalArgumentException ex) {
            errors.rejectValue(field, "invalidCompactRoleMappings", ex.getMessage());
        }
    }

    @AssertTrue(message = "entra.security.tenant-id must be a single tenant: 'common', 'organizations' and "
            + "'consumers' are not supported")
    public boolean isSingleTenant() {
        return tenantId == null || !MULTI_TENANT_AUTHORITIES.contains(tenantId.toLowerCase(Locale.ROOT));
    }

    @AssertTrue(message = "entra.security.tenant-id must be the tenant GUID (not a domain name) unless "
            + "entra.security.issuers is set explicitly, because Entra issuers always contain the GUID")
    public boolean isTenantIdUsableForIssuers() {
        return tenantId == null || !issuers.isEmpty() || GUID.matcher(tenantId).matches()
                || !isSingleTenant();
    }

    @AssertTrue(message = "entra.security.graph.overage-enabled=true requires entra.security.credential.type "
            + "(client-secret, certificate or workload-identity) so the API can call Microsoft Graph")
    public boolean isGraphCredentialConfigured() {
        return !graph.isOverageEnabled() || credential.getType() != CredentialType.NONE;
    }

    @AssertTrue(message = "every entra.security.outbound.clients.<name> needs a credential: set "
            + "entra.security.outbound.clients.<name>.credential.type or entra.security.credential.type")
    public boolean isOutboundCredentialConfigured() {
        return outbound.getClients().values().stream()
                .allMatch(c -> c.getCredential().getType() != CredentialType.NONE
                        || credential.getType() != CredentialType.NONE);
    }

    private static String trimSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    // ---------------------------------------------------------------- accessors

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId == null ? null : tenantId.trim();
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId == null ? null : clientId.trim();
    }

    public URI getAuthorityHost() {
        return authorityHost;
    }

    public void setAuthorityHost(URI authorityHost) {
        this.authorityHost = authorityHost;
    }

    public URI getJwkSetUri() {
        return jwkSetUri;
    }

    public void setJwkSetUri(URI jwkSetUri) {
        this.jwkSetUri = jwkSetUri;
    }

    public List<String> getAudiences() {
        return audiences;
    }

    public void setAudiences(List<String> audiences) {
        this.audiences = audiences;
    }

    public List<String> getIssuers() {
        return issuers;
    }

    public void setIssuers(List<String> issuers) {
        this.issuers = issuers;
    }

    public Duration getClockSkew() {
        return clockSkew;
    }

    public void setClockSkew(Duration clockSkew) {
        this.clockSkew = clockSkew;
    }

    public boolean isRequireTenantMatch() {
        return requireTenantMatch;
    }

    public void setRequireTenantMatch(boolean requireTenantMatch) {
        this.requireTenantMatch = requireTenantMatch;
    }

    public List<String> getPublicPaths() {
        return publicPaths;
    }

    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = publicPaths;
    }

    public Map<String, List<String>> getGroupRoleMappings() {
        return groupRoleMappings;
    }

    public void setGroupRoleMappings(Map<String, List<String>> groupRoleMappings) {
        this.groupRoleMappings = groupRoleMappings;
    }

    public Map<String, List<String>> getAppRoleMappings() {
        return appRoleMappings;
    }

    public void setAppRoleMappings(Map<String, List<String>> appRoleMappings) {
        this.appRoleMappings = appRoleMappings;
    }

    public String getGroupRoleMappingsCompact() {
        return groupRoleMappingsCompact;
    }

    public void setGroupRoleMappingsCompact(String groupRoleMappingsCompact) {
        this.groupRoleMappingsCompact = groupRoleMappingsCompact;
    }

    public String getAppRoleMappingsCompact() {
        return appRoleMappingsCompact;
    }

    public void setAppRoleMappingsCompact(String appRoleMappingsCompact) {
        this.appRoleMappingsCompact = appRoleMappingsCompact;
    }

    public String getClientRoleMappingsCompact() {
        return clientRoleMappingsCompact;
    }

    public void setClientRoleMappingsCompact(String clientRoleMappingsCompact) {
        this.clientRoleMappingsCompact = clientRoleMappingsCompact;
    }

    public Map<String, List<String>> getClientRoleMappings() {
        return clientRoleMappings;
    }

    public void setClientRoleMappings(Map<String, List<String>> clientRoleMappings) {
        this.clientRoleMappings = clientRoleMappings;
    }

    public User getUser() {
        return user;
    }

    public Service getService() {
        return service;
    }

    public Graph getGraph() {
        return graph;
    }

    public Credential getCredential() {
        return credential;
    }

    public Outbound getOutbound() {
        return outbound;
    }

    public Cache getCache() {
        return cache;
    }

    public Http getHttp() {
        return http;
    }

    public MethodSecurity getMethodSecurity() {
        return methodSecurity;
    }

    public Logging getLogging() {
        return logging;
    }

    // ---------------------------------------------------------------- nested types

    /** Settings for user (delegated) tokens. */
    public static class User {

        /** Whether the roles claim of user tokens (app roles assigned through the enterprise app) is mapped. */
        private boolean includeRolesClaim = true;

        /** Whether scp values are granted as SCOPE_{scope} authorities. */
        private boolean includeScopes = false;

        /** Roles granted to every authenticated user. */
        private List<String> defaultRoles = new ArrayList<>();

        public boolean isIncludeRolesClaim() {
            return includeRolesClaim;
        }

        public void setIncludeRolesClaim(boolean includeRolesClaim) {
            this.includeRolesClaim = includeRolesClaim;
        }

        public boolean isIncludeScopes() {
            return includeScopes;
        }

        public void setIncludeScopes(boolean includeScopes) {
            this.includeScopes = includeScopes;
        }

        public List<String> getDefaultRoles() {
            return defaultRoles;
        }

        public void setDefaultRoles(List<String> defaultRoles) {
            this.defaultRoles = defaultRoles;
        }
    }

    /** Settings for app-only (service) tokens. */
    public static class Service {

        /** Whether app roles without an app-role-mappings entry become ROLE_{value}. */
        private boolean mapUnmappedAppRoles = true;

        /** Reject app-only tokens whose azp/appid is not a key of client-role-mappings. */
        private boolean requireKnownClient = false;

        /** Roles granted to every authenticated service. */
        private List<String> defaultRoles = new ArrayList<>();

        public boolean isMapUnmappedAppRoles() {
            return mapUnmappedAppRoles;
        }

        public void setMapUnmappedAppRoles(boolean mapUnmappedAppRoles) {
            this.mapUnmappedAppRoles = mapUnmappedAppRoles;
        }

        public boolean isRequireKnownClient() {
            return requireKnownClient;
        }

        public void setRequireKnownClient(boolean requireKnownClient) {
            this.requireKnownClient = requireKnownClient;
        }

        public List<String> getDefaultRoles() {
            return defaultRoles;
        }

        public void setDefaultRoles(List<String> defaultRoles) {
            this.defaultRoles = defaultRoles;
        }
    }

    /** Microsoft Graph lookup for group overage. */
    public static class Graph {

        /** Resolve groups through Microsoft Graph when the token signals group overage. */
        private boolean overageEnabled = false;

        /** Microsoft Graph base URL. */
        @NotNull
        private URI baseUrl = URI.create("https://graph.microsoft.com");

        /** Scope requested for Graph tokens. */
        @NotBlank
        private String scope = "https://graph.microsoft.com/.default";

        /** How long resolved memberships are cached per user. */
        @NotNull
        private Duration cacheTtl = Duration.ofMinutes(10);

        /** Maximum number of users whose memberships are cached. */
        @Min(1)
        private int cacheMaxEntries = 10_000;

        /** Maximum number of Graph result pages followed per lookup. */
        @Min(1)
        private int maxPages = 20;

        public boolean isOverageEnabled() {
            return overageEnabled;
        }

        public void setOverageEnabled(boolean overageEnabled) {
            this.overageEnabled = overageEnabled;
        }

        public URI getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(URI baseUrl) {
            this.baseUrl = baseUrl;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public Duration getCacheTtl() {
            return cacheTtl;
        }

        public void setCacheTtl(Duration cacheTtl) {
            this.cacheTtl = cacheTtl;
        }

        public int getCacheMaxEntries() {
            return cacheMaxEntries;
        }

        public void setCacheMaxEntries(int cacheMaxEntries) {
            this.cacheMaxEntries = cacheMaxEntries;
        }

        public int getMaxPages() {
            return maxPages;
        }

        public void setMaxPages(int maxPages) {
            this.maxPages = maxPages;
        }
    }

    /** How a credential authenticates to Entra ID. */
    public enum CredentialType {
        /** No credential. */
        NONE,
        /** Client secret. */
        CLIENT_SECRET,
        /** Certificate (PEM with a PKCS#8 key, optionally encrypted, or PKCS#12). */
        CERTIFICATE,
        /** Azure Workload Identity federated token file (AKS). */
        WORKLOAD_IDENTITY
    }

    /** A confidential-client credential. */
    public static class Credential {

        /** Credential type: none, client-secret, certificate or workload-identity. */
        @NotNull
        private CredentialType type = CredentialType.NONE;

        /** Tenant to request tokens from. Defaults to entra.security.tenant-id (or AZURE_TENANT_ID for workload identity). */
        private String tenantId;

        /** Client id requesting tokens. Defaults to entra.security.client-id (or AZURE_CLIENT_ID for workload identity). */
        private String clientId;

        /** Client secret, for type client-secret. Supply it from a Kubernetes Secret. */
        private String clientSecret;

        /** PEM (certificate + PKCS#8 key) or PKCS#12 (.p12/.pfx) file, for type certificate. */
        private String certificatePath;

        /**
         * For type certificate: the PKCS#12 keystore password, or the password of an encrypted PEM private key
         * (ENCRYPTED PRIVATE KEY). Supply it from a Kubernetes Secret.
         */
        private String certificatePassword;

        /** Federated token file, for type workload-identity. Defaults to AZURE_FEDERATED_TOKEN_FILE. */
        private String federatedTokenFile;

        @AssertTrue(message = "credential.client-secret is required when credential.type is client-secret")
        public boolean isClientSecretPresent() {
            return type != CredentialType.CLIENT_SECRET || hasText(clientSecret);
        }

        @AssertTrue(message = "credential.certificate-path is required when credential.type is certificate")
        public boolean isCertificatePathPresent() {
            return type != CredentialType.CERTIFICATE || hasText(certificatePath);
        }

        private static boolean hasText(String value) {
            return value != null && !value.isBlank();
        }

        public CredentialType getType() {
            return type;
        }

        public void setType(CredentialType type) {
            this.type = type;
        }

        public String getTenantId() {
            return tenantId;
        }

        public void setTenantId(String tenantId) {
            this.tenantId = tenantId;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getCertificatePath() {
            return certificatePath;
        }

        public void setCertificatePath(String certificatePath) {
            this.certificatePath = certificatePath;
        }

        public String getCertificatePassword() {
            return certificatePassword;
        }

        public void setCertificatePassword(String certificatePassword) {
            this.certificatePassword = certificatePassword;
        }

        public String getFederatedTokenFile() {
            return federatedTokenFile;
        }

        public void setFederatedTokenFile(String federatedTokenFile) {
            this.federatedTokenFile = federatedTokenFile;
        }
    }

    /** Outbound (service-to-service) clients. */
    public static class Outbound {

        /** Named outbound clients, for example orders-api. */
        @Valid
        private Map<String, OutboundClient> clients = new LinkedHashMap<>();

        public Map<String, OutboundClient> getClients() {
            return clients;
        }

        public void setClients(Map<String, OutboundClient> clients) {
            this.clients = clients;
        }
    }

    /** How an outbound client gets its tokens. */
    public enum OutboundFlow {
        /** App-only tokens with the client credentials grant (the default). */
        CLIENT_CREDENTIALS,
        /** Delegated tokens for the current user, exchanged with the on-behalf-of (jwt-bearer) grant. */
        ON_BEHALF_OF
    }

    /** A peer API this service calls, with an app-only token or on behalf of the current user. */
    public static class OutboundClient {

        /** Token flow: client-credentials (app-only) or on-behalf-of (as the calling user). */
        @NotNull
        private OutboundFlow flow = OutboundFlow.CLIENT_CREDENTIALS;

        /**
         * Scope to request: api://{peer-client-id}/.default for client-credentials; for on-behalf-of, the
         * delegated scopes (space separated, for example api://{peer-client-id}/Orders.Read) or .default.
         */
        @NotBlank(message = "must be set, for example api://<peer-client-id>/.default")
        private String scope;

        /** Optional base URL of the peer, available to callers through EntraOutboundClients. */
        private URI baseUrl;

        /** Credential for this client. Defaults to entra.security.credential. */
        @Valid
        private final Credential credential = new Credential();

        public OutboundFlow getFlow() {
            return flow;
        }

        public void setFlow(OutboundFlow flow) {
            this.flow = flow;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public URI getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(URI baseUrl) {
            this.baseUrl = baseUrl;
        }

        public Credential getCredential() {
            return credential;
        }
    }

    /** Cache settings. */
    public static class Cache {

        /** How long the JWKS is cached before it is refreshed. */
        @NotNull
        private Duration jwksTtl = Duration.ofMinutes(15);

        /** How long before expiry an acquired outbound/Graph token is renewed. */
        @NotNull
        private Duration tokenRefreshSkew = Duration.ofMinutes(5);

        /** Maximum number of on-behalf-of tokens cached per outbound client (one per user and scope). */
        @Min(1)
        private int onBehalfOfMaxEntries = 10_000;

        public int getOnBehalfOfMaxEntries() {
            return onBehalfOfMaxEntries;
        }

        public void setOnBehalfOfMaxEntries(int onBehalfOfMaxEntries) {
            this.onBehalfOfMaxEntries = onBehalfOfMaxEntries;
        }

        public Duration getJwksTtl() {
            return jwksTtl;
        }

        public void setJwksTtl(Duration jwksTtl) {
            this.jwksTtl = jwksTtl;
        }

        public Duration getTokenRefreshSkew() {
            return tokenRefreshSkew;
        }

        public void setTokenRefreshSkew(Duration tokenRefreshSkew) {
            this.tokenRefreshSkew = tokenRefreshSkew;
        }
    }

    /** HTTP client settings for JWKS, token and Graph calls. */
    public static class Http {

        /** Connect timeout. */
        @NotNull
        private Duration connectTimeout = Duration.ofSeconds(5);

        /** Read timeout. */
        @NotNull
        private Duration readTimeout = Duration.ofSeconds(10);

        public Duration getConnectTimeout() {
            return connectTimeout;
        }

        public void setConnectTimeout(Duration connectTimeout) {
            this.connectTimeout = connectTimeout;
        }

        public Duration getReadTimeout() {
            return readTimeout;
        }

        public void setReadTimeout(Duration readTimeout) {
            this.readTimeout = readTimeout;
        }
    }

    /** Method security settings. */
    public static class MethodSecurity {

        /** Enable @Secured, @PreAuthorize and @RolesAllowed without @EnableMethodSecurity. */
        private boolean enabled = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /** Logging settings. */
    public static class Logging {

        /** Log a privacy-safe claim summary of each accepted token at DEBUG. */
        private boolean logClaims = false;

        public boolean isLogClaims() {
            return logClaims;
        }

        public void setLogClaims(boolean logClaims) {
            this.logClaims = logClaims;
        }
    }
}
