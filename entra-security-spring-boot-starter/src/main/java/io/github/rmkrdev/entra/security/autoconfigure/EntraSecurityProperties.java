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
import io.github.rmkrdev.entra.security.core.decision.AuditLogger;
import io.github.rmkrdev.entra.security.core.outbound.OutboundTarget;

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
    private static final String PATH_SEGMENT = "[A-Za-z0-9._~%:@!$&'()*+,;=-]+";
    private static final Pattern TENANT_PATH = Pattern.compile(
            "^(?!.*\\.\\.)" + PATH_SEGMENT + "(/" + PATH_SEGMENT + ")*$");

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

    /**
     * Entra authority host. Change it for sovereign clouds, for example https://login.microsoftonline.us.
     * {@code entra.security.authority.host} takes precedence when set.
     */
    @NotNull
    private URI authorityHost = URI.create("https://login.microsoftonline.com");

    /**
     * JWKS endpoint. Defaults to {authority-host}/{tenant-id}/discovery/v2.0/keys.
     * {@code entra.security.authority.jwks-uri} takes precedence when set.
     */
    private URI jwkSetUri;

    /** Accepted token audiences. Defaults to api://{client-id} and {client-id}. */
    private List<String> audiences = new ArrayList<>();

    /**
     * Accepted token issuers. Defaults to the tenant's v1 (sts.windows.net) and v2 issuers.
     * {@code entra.security.authority.issuers} takes precedence when set.
     */
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

    /** Overrides for the authority endpoints: sovereign clouds, B2C/CIAM, custom domains and other IdPs. */
    @Valid
    private final Authority authority = new Authority();

    /** How bearer tokens are validated: locally with JWKS (default), remotely, or both. */
    @Valid
    private final Validation validation = new Validation();

    /**
     * Optional allow-list of directory tenants. Off by default, which keeps a single {@code tenant-id}.
     */
    @Valid
    private final MultiTenant multiTenant = new MultiTenant();

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

    @Valid
    private final Observability observability = new Observability();

    /** Metrics backend settings. */
    private final Monitoring monitoring = new Monitoring();

    private final Audit audit = new Audit();

    private final Authorization authorization = new Authorization();

    private final SelfCheck selfCheck = new SelfCheck();

    private final Cae cae = new Cae();

    // ---------------------------------------------------------------- derived values

    /**
     * The effective issuers, without OIDC discovery: {@code authority.issuers}, then {@code issuers}, then the
     * tenant's v2 issuer on the authority host and its v1 (sts.windows.net) issuer.
     */
    public Set<String> resolveIssuers() {
        if (!authority.getIssuers().isEmpty()) {
            return new LinkedHashSet<>(authority.getIssuers());
        }
        if (!issuers.isEmpty()) {
            return new LinkedHashSet<>(issuers);
        }
        Set<String> result = new LinkedHashSet<>();
        if (multiTenant.isEnabled()) {
            for (String id : resolveAcceptedTenantIds()) {
                addTenantIssuers(result, id);
            }
            if (!result.isEmpty()) {
                return result;
            }
        }
        addTenantIssuers(result, tenantId);
        return result;
    }

    /**
     * Directory ids whose tokens are accepted when {@code entra.security.multi-tenant.enabled} is true.
     * A GUID {@code tenant-id} is included. Empty when the flag is off.
     */
    public Set<String> resolveAcceptedTenantIds() {
        if (!multiTenant.isEnabled()) {
            return Set.of();
        }
        LinkedHashSet<String> ids = new LinkedHashSet<>();
        if (tenantId != null && GUID.matcher(tenantId).matches()) {
            ids.add(tenantId);
        }
        for (String id : multiTenant.getTenantIds()) {
            if (id != null && !id.isBlank()) {
                ids.add(id.trim());
            }
        }
        return ids;
    }

    private void addTenantIssuers(Set<String> result, String id) {
        result.add(trimSlash(resolveAuthorityHost().toString()) + "/" + id + "/v2.0");
        result.add("https://sts.windows.net/" + id + "/");
    }

    /** The effective audiences: the configured ones, or api://{client-id} and {client-id}. */
    public Set<String> resolveAudiences() {
        if (!audiences.isEmpty()) {
            return new LinkedHashSet<>(audiences);
        }
        return new LinkedHashSet<>(List.of("api://" + clientId, clientId));
    }

    /** The effective authority host: {@code authority.host}, then {@code authority-host}. */
    public URI resolveAuthorityHost() {
        return authority.getHost() != null ? authority.getHost() : authorityHost;
    }

    /**
     * The path segment after the authority host that endpoints are built from: {@code authority.tenant-path}, or
     * the tenant id.
     */
    public String resolveTenantPath() {
        String path = authority.getTenantPath();
        return path != null && !path.isBlank() ? path : tenantId;
    }

    /** The effective JWKS endpoint, without OIDC discovery. */
    public URI resolveJwkSetUri() {
        if (authority.getJwksUri() != null) {
            return authority.getJwksUri();
        }
        if (jwkSetUri != null) {
            return jwkSetUri;
        }
        if (multiTenant.isEnabled()) {
            return URI.create(trimSlash(resolveAuthorityHost().toString()) + "/common/discovery/v2.0/keys");
        }
        return authorityUri("/discovery/v2.0/keys");
    }

    /** The effective v2 token endpoint of this API's tenant, without OIDC discovery. */
    public URI resolveTokenEndpoint() {
        return authority.getTokenEndpoint() != null ? authority.getTokenEndpoint()
                : authorityUri("/oauth2/v2.0/token");
    }

    /** The effective v2 authorize endpoint, without OIDC discovery. */
    public URI resolveAuthorizeEndpoint() {
        return authority.getAuthorizeEndpoint() != null ? authority.getAuthorizeEndpoint()
                : authorityUri("/oauth2/v2.0/authorize");
    }

    /** The OIDC discovery document: {@code authority.metadata-uri}, or the tenant's v2 openid-configuration. */
    public URI resolveMetadataUri() {
        return authority.getMetadataUri() != null ? authority.getMetadataUri()
                : authorityUri("/v2.0/.well-known/openid-configuration");
    }

    /** The effective Microsoft Graph base URL: {@code authority.graph-base-url}, then {@code graph.base-url}. */
    public URI resolveGraphBaseUrl() {
        return authority.getGraphBaseUrl() != null ? authority.getGraphBaseUrl() : graph.getBaseUrl();
    }

    /** The effective userinfo endpoint, without OIDC discovery: the configured one, or Graph's OIDC userinfo. */
    public URI resolveUserinfoEndpoint() {
        return authority.getUserinfoEndpoint() != null ? authority.getUserinfoEndpoint()
                : URI.create(trimSlash(resolveGraphBaseUrl().toString()) + "/oidc/userinfo");
    }

    /** Whether OIDC discovery fills the endpoints that are not configured. */
    public boolean isDiscoveryActive() {
        return authority.getDiscovery().isEnabled() || authority.getMetadataUri() != null;
    }

    private URI authorityUri(String suffix) {
        return URI.create(trimSlash(resolveAuthorityHost().toString()) + "/" + resolveTenantPath() + suffix);
    }

    /**
     * The {@code tid} every token must carry, or {@code null} when the check is off or the tenant is not
     * a GUID (domain tenants are covered by the explicit issuers instead).
     */
    public String resolveRequiredTenantId() {
        if (multiTenant.isEnabled()) {
            return null;
        }
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
        properties.getAuthority().validate(errors);
        properties.getOutbound().validate(errors);
        String introspectionUri = Authority.uriProblem(properties.getValidation().getIntrospection().getUri(),
                properties.getAuthority().isAllowHttp());
        if (introspectionUri != null) {
            errors.rejectValue("validation.introspection.uri", "invalidIntrospectionUri",
                    PREFIX + ".validation.introspection.uri " + introspectionUri);
        }
    }

    private static void validateCompact(Errors errors, String field, Runnable resolve) {
        try {
            resolve.run();
        }
        catch (IllegalArgumentException ex) {
            errors.rejectValue(field, "invalidCompactRoleMappings", ex.getMessage());
        }
    }

    @AssertTrue(message = "entra.security.tenant-id values 'common' and 'organizations' require "
            + "entra.security.multi-tenant.enabled=true; 'consumers' is not supported")
    public boolean isSingleTenant() {
        if (tenantId == null) {
            return true;
        }
        String value = tenantId.toLowerCase(Locale.ROOT);
        if (!MULTI_TENANT_AUTHORITIES.contains(value)) {
            return true;
        }
        if ("consumers".equals(value)) {
            return false;
        }
        return multiTenant.isEnabled();
    }

    @AssertTrue(message = "entra.security.multi-tenant.enabled=true requires at least one directory GUID in "
            + "entra.security.multi-tenant.tenant-ids or a GUID entra.security.tenant-id")
    public boolean isMultiTenantConfigured() {
        if (!multiTenant.isEnabled()) {
            return true;
        }
        if ("consumers".equalsIgnoreCase(tenantId)) {
            return false;
        }
        for (String id : resolveAcceptedTenantIds()) {
            if (!GUID.matcher(id).matches()) {
                return false;
            }
        }
        return !resolveAcceptedTenantIds().isEmpty();
    }

    @AssertTrue(message = "entra.security.tenant-id must be the tenant GUID (not a domain name) unless "
            + "entra.security.authority.issuers (or entra.security.issuers) is set explicitly, OIDC discovery is "
            + "enabled, or entra.security.multi-tenant.enabled=true with a tenant allow-list, because Entra issuers "
            + "always contain the GUID")
    public boolean isTenantIdUsableForIssuers() {
        if (tenantId == null || !issuers.isEmpty() || !authority.getIssuers().isEmpty() || isDiscoveryActive()) {
            return true;
        }
        if (GUID.matcher(tenantId).matches()) {
            return true;
        }
        return multiTenant.isEnabled() && !resolveAcceptedTenantIds().isEmpty();
    }

    @AssertTrue(message = "entra.security.validation.introspection.auth-method=bearer requires "
            + "entra.security.credential.type and entra.security.validation.introspection.scope")
    public boolean isIntrospectionBearerConfigured() {
        Introspection introspection = validation.getIntrospection();
        return validation.getMode() == ValidationMode.JWKS || introspection.getType() != IntrospectionType.RFC7662
                || introspection.getAuthMethod() != IntrospectionAuthMethod.BEARER
                || (credential.getType() != CredentialType.NONE && introspection.getScope() != null
                        && !introspection.getScope().isBlank());
    }

    @AssertTrue(message = "entra.security.validation.introspection.auth-method client-secret-basic or "
            + "client-secret-post requires entra.security.validation.introspection.client-secret (or "
            + "entra.security.credential.client-secret)")
    public boolean isIntrospectionSecretConfigured() {
        Introspection introspection = validation.getIntrospection();
        return validation.getMode() == ValidationMode.JWKS || introspection.getType() != IntrospectionType.RFC7662
                || (introspection.getAuthMethod() != IntrospectionAuthMethod.CLIENT_SECRET_BASIC
                        && introspection.getAuthMethod() != IntrospectionAuthMethod.CLIENT_SECRET_POST)
                || resolveIntrospectionClientSecret() != null;
    }

    /** The client id for introspection client authentication. */
    public String resolveIntrospectionClientId() {
        String id = validation.getIntrospection().getClientId();
        return id != null && !id.isBlank() ? id : clientId;
    }

    /** The client secret for introspection client authentication, or {@code null}. */
    public String resolveIntrospectionClientSecret() {
        String secret = validation.getIntrospection().getClientSecret();
        if (secret != null && !secret.isBlank()) {
            return secret;
        }
        String own = credential.getClientSecret();
        return own != null && !own.isBlank() ? own : null;
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

    public Authority getAuthority() {
        return authority;
    }

    public Validation getValidation() {
        return validation;
    }

    public MultiTenant getMultiTenant() {
        return multiTenant;
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

    public Observability getObservability() {
        return observability;
    }

    public Monitoring getMonitoring() {
        return monitoring;
    }

    public Audit getAudit() {
        return audit;
    }

    public Authorization getAuthorization() {
        return authorization;
    }

    public SelfCheck getSelfCheck() {
        return selfCheck;
    }

    public Cae getCae() {
        return cae;
    }

    // ---------------------------------------------------------------- nested types

    /**
     * Overrides for the authority endpoints, all optional. Unset values keep the Entra defaults, which are built
     * from {@code {host}/{tenant-path}}; with discovery enabled they are taken from the OIDC metadata document
     * instead. Explicit values always win over discovered ones.
     */
    public static class Authority {

        private static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "[::1]", "::1");

        /**
         * Authority host, for example https://login.microsoftonline.us (US Government),
         * https://login.chinacloudapi.cn, https://contoso.b2clogin.com, https://contoso.ciamlogin.com or a custom
         * domain. Overrides entra.security.authority-host.
         */
        private URI host;

        /**
         * Path after the host that endpoints are built from. Defaults to the tenant id. For B2C use
         * {tenant}.onmicrosoft.com/{policy}, for example contoso.onmicrosoft.com/B2C_1_signin.
         */
        private String tenantPath;

        /** Accepted issuers. Overrides entra.security.issuers and the discovered issuer. */
        private List<String> issuers = new ArrayList<>();

        /** JWKS endpoint. Overrides entra.security.jwk-set-uri and the discovered jwks_uri. */
        private URI jwksUri;

        /** Token endpoint used for client-credentials, on-behalf-of and Graph tokens of this API's tenant. */
        private URI tokenEndpoint;

        /** Authorize endpoint. Not called by the starter; exposed through EntraEndpoints for applications. */
        private URI authorizeEndpoint;

        /**
         * OIDC discovery (metadata) document. Defaults to {host}/{tenant-path}/v2.0/.well-known/openid-configuration.
         * Setting it turns discovery on.
         */
        private URI metadataUri;

        /** Userinfo endpoint. Defaults to the discovered userinfo_endpoint, or {graph-base-url}/oidc/userinfo. */
        private URI userinfoEndpoint;

        /** Microsoft Graph base URL. Overrides entra.security.graph.base-url, for example https://graph.microsoft.us. */
        private URI graphBaseUrl;

        /**
         * Allow plain http endpoints on hosts other than localhost, for example an in-cluster IdP at
         * http://idp.auth.svc.cluster.local. Keep it off in production unless the hop is otherwise protected.
         */
        private boolean allowHttp = false;

        private final Discovery discovery = new Discovery();

        void validate(Errors errors) {
            checkUri(errors, "host", host);
            checkUri(errors, "jwksUri", jwksUri);
            checkUri(errors, "tokenEndpoint", tokenEndpoint);
            checkUri(errors, "authorizeEndpoint", authorizeEndpoint);
            checkUri(errors, "metadataUri", metadataUri);
            checkUri(errors, "userinfoEndpoint", userinfoEndpoint);
            checkUri(errors, "graphBaseUrl", graphBaseUrl);
            if (tenantPath != null && !tenantPath.isBlank() && !TENANT_PATH.matcher(tenantPath).matches()) {
                errors.rejectValue("authority.tenantPath", "invalidTenantPath", PREFIX + ".authority.tenant-path '"
                        + tenantPath + "' must be one or more path segments without '..', '?' or '#', for example "
                        + "contoso.onmicrosoft.com/B2C_1_signin");
            }
            for (int i = 0; i < issuers.size(); i++) {
                String issuer = issuers.get(i);
                if (issuer == null || issuer.isBlank()) {
                    errors.rejectValue("authority.issuers", "blankIssuer",
                            PREFIX + ".authority.issuers[" + i + "] must not be blank");
                }
            }
        }

        private void checkUri(Errors errors, String field, URI uri) {
            String problem = uriProblem(uri, allowHttp);
            if (problem != null) {
                errors.rejectValue("authority." + field, "invalidAuthorityUri",
                        PREFIX + ".authority." + kebab(field) + " " + problem);
            }
        }

        /**
         * Why an authority URI is not acceptable, or {@code null} when it is (or is {@code null}).
         */
        static String uriProblem(URI uri, boolean allowHttp) {
            if (uri == null) {
                return null;
            }
            if (!uri.isAbsolute() || uri.getHost() == null) {
                return "'" + uri + "' must be an absolute http(s) URL with a host";
            }
            String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
            if ("https".equals(scheme)) {
                return null;
            }
            if (!"http".equals(scheme)) {
                return "'" + uri + "' must use https";
            }
            if (allowHttp || LOOPBACK.contains(uri.getHost().toLowerCase(Locale.ROOT))) {
                return null;
            }
            return "'" + uri + "' uses http: use https, or set " + PREFIX + ".authority.allow-http=true for an "
                    + "endpoint that is protected otherwise (for example an in-cluster IdP)";
        }

        private static String kebab(String field) {
            return field.replaceAll("([a-z])([A-Z])", "$1-$2").toLowerCase(Locale.ROOT);
        }

        public URI getHost() {
            return host;
        }

        public void setHost(URI host) {
            this.host = host;
        }

        public String getTenantPath() {
            return tenantPath;
        }

        public void setTenantPath(String tenantPath) {
            this.tenantPath = tenantPath == null ? null : stripSlashes(tenantPath.trim());
        }

        public List<String> getIssuers() {
            return issuers;
        }

        public void setIssuers(List<String> issuers) {
            this.issuers = issuers;
        }

        public URI getJwksUri() {
            return jwksUri;
        }

        public void setJwksUri(URI jwksUri) {
            this.jwksUri = jwksUri;
        }

        public URI getTokenEndpoint() {
            return tokenEndpoint;
        }

        public void setTokenEndpoint(URI tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
        }

        public URI getAuthorizeEndpoint() {
            return authorizeEndpoint;
        }

        public void setAuthorizeEndpoint(URI authorizeEndpoint) {
            this.authorizeEndpoint = authorizeEndpoint;
        }

        public URI getMetadataUri() {
            return metadataUri;
        }

        public void setMetadataUri(URI metadataUri) {
            this.metadataUri = metadataUri;
        }

        public URI getUserinfoEndpoint() {
            return userinfoEndpoint;
        }

        public void setUserinfoEndpoint(URI userinfoEndpoint) {
            this.userinfoEndpoint = userinfoEndpoint;
        }

        public URI getGraphBaseUrl() {
            return graphBaseUrl;
        }

        public void setGraphBaseUrl(URI graphBaseUrl) {
            this.graphBaseUrl = graphBaseUrl;
        }

        public boolean isAllowHttp() {
            return allowHttp;
        }

        public void setAllowHttp(boolean allowHttp) {
            this.allowHttp = allowHttp;
        }

        public Discovery getDiscovery() {
            return discovery;
        }

        private static String stripSlashes(String value) {
            String result = value;
            while (result.startsWith("/")) {
                result = result.substring(1);
            }
            while (result.endsWith("/")) {
                result = result.substring(0, result.length() - 1);
            }
            return result;
        }
    }

    /** OIDC discovery of the authority endpoints. */
    public static class Discovery {

        /** Fetch the OIDC metadata document at startup and use it for every endpoint that is not configured. */
        private boolean enabled = false;

        /**
         * Fail startup when the metadata document cannot be fetched or is invalid. When false, a warning is
         * logged and the defaults are used.
         */
        private boolean required = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isRequired() {
            return required;
        }

        public void setRequired(boolean required) {
            this.required = required;
        }
    }

    /** How bearer tokens are validated. */
    public enum ValidationMode {
        /** Locally, against the signing keys from the JWKS endpoint. Recommended and fastest. */
        JWKS,
        /** Remotely, with the introspection (RFC 7662) or userinfo check only. */
        INTROSPECTION,
        /** JWKS first, then the remote check (see {@link Validation#getHybridStrategy()}). */
        HYBRID
    }

    /** How hybrid validation combines the two checks. */
    public enum HybridStrategy {
        /** The token must pass JWKS validation and the remote check (catches revoked tokens). */
        BOTH,
        /** Signed JWTs are validated with JWKS only; opaque tokens go to the remote check. */
        FALLBACK
    }

    /** Which remote check runs. */
    public enum IntrospectionType {
        /** An RFC 7662 token introspection endpoint (gateways and custom authorization servers; not Entra ID). */
        RFC7662,
        /** Present the token to a userinfo-style endpoint such as Graph /oidc/userinfo or /v1.0/me. */
        USERINFO
    }

    /** How this API authenticates to an RFC 7662 endpoint. */
    public enum IntrospectionAuthMethod {
        /** HTTP Basic with client id and secret. */
        CLIENT_SECRET_BASIC,
        /** Client id and secret in the form body. */
        CLIENT_SECRET_POST,
        /** An app-only bearer token from entra.security.credential for introspection.scope. */
        BEARER,
        /** No client authentication. */
        NONE
    }

    /** Token validation settings. */
    public static class Validation {

        /** jwks (default), introspection or hybrid. */
        @NotNull
        private ValidationMode mode = ValidationMode.JWKS;

        /** For hybrid: both (default) or fallback. */
        @NotNull
        private HybridStrategy hybridStrategy = HybridStrategy.BOTH;

        /**
         * Reject tokens that do not carry {@code idtyp}, {@code scp} or {@code roles}. An ID token whose
         * {@code aud} is this API's client id is then rejected. Off by default.
         */
        private boolean rejectIdTokens = false;

        @Valid
        private final Introspection introspection = new Introspection();

        public ValidationMode getMode() {
            return mode;
        }

        public void setMode(ValidationMode mode) {
            this.mode = mode;
        }

        public HybridStrategy getHybridStrategy() {
            return hybridStrategy;
        }

        public void setHybridStrategy(HybridStrategy hybridStrategy) {
            this.hybridStrategy = hybridStrategy;
        }

        public boolean isRejectIdTokens() {
            return rejectIdTokens;
        }

        public void setRejectIdTokens(boolean rejectIdTokens) {
            this.rejectIdTokens = rejectIdTokens;
        }

        public Introspection getIntrospection() {
            return introspection;
        }
    }

    /**
     * Allow-list of Entra directory tenants. {@code enabled} is the single switch; leave it {@code false} for a
     * single-tenant API.
     */
    public static class MultiTenant {

        /** Accept tokens whose {@code tid} is in {@code tenant-ids} (and a GUID {@code tenant-id}). */
        private boolean enabled = false;

        /** Directory (tenant) GUIDs that may call this API when {@code enabled} is true. */
        private List<String> tenantIds = new ArrayList<>();

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getTenantIds() {
            return tenantIds;
        }

        public void setTenantIds(List<String> tenantIds) {
            this.tenantIds = tenantIds;
        }
    }

    /** The remote token check used by validation modes introspection and hybrid. */
    public static class Introspection {

        /** rfc7662 (default) or userinfo. */
        @NotNull
        private IntrospectionType type = IntrospectionType.RFC7662;

        /**
         * Endpoint to call. Defaults to the discovered introspection_endpoint for rfc7662, and to the authority
         * userinfo endpoint (Graph /oidc/userinfo by default) for userinfo.
         */
        private URI uri;

        /** Client authentication for rfc7662. */
        @NotNull
        private IntrospectionAuthMethod authMethod = IntrospectionAuthMethod.CLIENT_SECRET_BASIC;

        /** Client id for client-secret-basic/post. Defaults to entra.security.client-id. */
        private String clientId;

        /** Client secret for client-secret-basic/post. Defaults to entra.security.credential.client-secret. */
        private String clientSecret;

        /** Scope of the app-only token for auth-method bearer, for example api://gateway/.default. */
        private String scope;

        /** token_type_hint sent with rfc7662 requests. Empty to omit it. */
        private String tokenTypeHint = "access_token";

        /**
         * Check exp/nbf, iss, aud and tid of the introspected claims with the same rules as JWKS validation.
         * Applies to rfc7662; userinfo checks only the timestamps, since those tokens are for Graph.
         */
        private boolean validateClaims = true;

        /** Extra claim mappings, target claim to response field, for example oid: user_id or roles: groups. */
        private Map<String, String> claimsMapping = new LinkedHashMap<>();

        /** Connect timeout of the remote check. */
        @NotNull
        private Duration connectTimeout = Duration.ofSeconds(2);

        /** Read timeout of the remote check. */
        @NotNull
        private Duration readTimeout = Duration.ofSeconds(3);

        /** Active results are cached until the token expires or this passes, whichever is first. */
        @NotNull
        private Duration positiveCacheTtl = Duration.ofMinutes(5);

        /** Inactive results are cached this long. */
        @NotNull
        private Duration negativeCacheTtl = Duration.ofSeconds(10);

        /** Maximum number of cached results. */
        @Min(1)
        private int cacheMaxEntries = 10_000;

        /** Consecutive failures that open the circuit breaker. */
        @Min(1)
        private int failureThreshold = 5;

        /** How long the circuit stays open (tokens that are not cached are rejected) before one trial call. */
        @NotNull
        private Duration openDuration = Duration.ofSeconds(30);

        public IntrospectionType getType() {
            return type;
        }

        public void setType(IntrospectionType type) {
            this.type = type;
        }

        public URI getUri() {
            return uri;
        }

        public void setUri(URI uri) {
            this.uri = uri;
        }

        public IntrospectionAuthMethod getAuthMethod() {
            return authMethod;
        }

        public void setAuthMethod(IntrospectionAuthMethod authMethod) {
            this.authMethod = authMethod;
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

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public String getTokenTypeHint() {
            return tokenTypeHint;
        }

        public void setTokenTypeHint(String tokenTypeHint) {
            this.tokenTypeHint = tokenTypeHint;
        }

        public boolean isValidateClaims() {
            return validateClaims;
        }

        public void setValidateClaims(boolean validateClaims) {
            this.validateClaims = validateClaims;
        }

        public Map<String, String> getClaimsMapping() {
            return claimsMapping;
        }

        public void setClaimsMapping(Map<String, String> claimsMapping) {
            this.claimsMapping = claimsMapping;
        }

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

        public Duration getPositiveCacheTtl() {
            return positiveCacheTtl;
        }

        public void setPositiveCacheTtl(Duration positiveCacheTtl) {
            this.positiveCacheTtl = positiveCacheTtl;
        }

        public Duration getNegativeCacheTtl() {
            return negativeCacheTtl;
        }

        public void setNegativeCacheTtl(Duration negativeCacheTtl) {
            this.negativeCacheTtl = negativeCacheTtl;
        }

        public int getCacheMaxEntries() {
            return cacheMaxEntries;
        }

        public void setCacheMaxEntries(int cacheMaxEntries) {
            this.cacheMaxEntries = cacheMaxEntries;
        }

        public int getFailureThreshold() {
            return failureThreshold;
        }

        public void setFailureThreshold(int failureThreshold) {
            this.failureThreshold = failureThreshold;
        }

        public Duration getOpenDuration() {
            return openDuration;
        }

        public void setOpenDuration(Duration openDuration) {
            this.openDuration = openDuration;
        }
    }

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
        WORKLOAD_IDENTITY,
        /**
         * Certificate stored in Azure Key Vault, read with managed identity or workload identity and reloaded
         * periodically. Needs azure-identity and azure-security-keyvault-secrets (or -certificates).
         */
        KEY_VAULT_CERTIFICATE
    }

    /** A confidential-client credential. */
    public static class Credential {

        /** Credential type: none, client-secret, certificate, workload-identity or key-vault-certificate. */
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

        /** Key Vault certificate, for type key-vault-certificate. */
        @Valid
        private final KeyVault keyVault = new KeyVault();

        @AssertTrue(message = "credential.client-secret is required when credential.type is client-secret")
        public boolean isClientSecretPresent() {
            return type != CredentialType.CLIENT_SECRET || hasText(clientSecret);
        }

        @AssertTrue(message = "credential.certificate-path is required when credential.type is certificate")
        public boolean isCertificatePathPresent() {
            return type != CredentialType.CERTIFICATE || hasText(certificatePath);
        }

        @AssertTrue(message = "credential.key-vault.vault-url and credential.key-vault.certificate-name are required "
                + "when credential.type is key-vault-certificate")
        public boolean isKeyVaultCertificateConfigured() {
            return type != CredentialType.KEY_VAULT_CERTIFICATE
                    || (keyVault.getVaultUrl() != null && hasText(keyVault.getCertificateName()));
        }

        @AssertTrue(message = "credential.key-vault.vault-url must be an https URL, for example "
                + "https://<vault-name>.vault.azure.net")
        public boolean isKeyVaultUrlHttps() {
            return keyVault.getVaultUrl() == null || "https".equalsIgnoreCase(keyVault.getVaultUrl().getScheme());
        }

        public KeyVault getKeyVault() {
            return keyVault;
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

    /** A client certificate kept in Azure Key Vault. */
    public static class KeyVault {

        /** Vault URL, for example https://my-vault.vault.azure.net. */
        private URI vaultUrl;

        /** Name of the Key Vault certificate. Its private key must be exportable (the default). */
        private String certificateName;

        /** Certificate version. Defaults to the latest version, so rotations are picked up on refresh. */
        private String certificateVersion;

        /** How often the certificate is reloaded from Key Vault. */
        @NotNull
        private Duration refreshInterval = Duration.ofHours(1);

        /** How long to wait before retrying after a failed reload. The cached certificate is used meanwhile. */
        @NotNull
        private Duration retryInterval = Duration.ofMinutes(1);

        /**
         * Client id of the user-assigned managed identity or workload identity used to read the vault. Defaults
         * to AZURE_CLIENT_ID (set by the AKS workload identity webhook) or the system-assigned identity.
         */
        private String identityClientId;

        public URI getVaultUrl() {
            return vaultUrl;
        }

        public void setVaultUrl(URI vaultUrl) {
            this.vaultUrl = vaultUrl;
        }

        public String getCertificateName() {
            return certificateName;
        }

        public void setCertificateName(String certificateName) {
            this.certificateName = certificateName;
        }

        public String getCertificateVersion() {
            return certificateVersion;
        }

        public void setCertificateVersion(String certificateVersion) {
            this.certificateVersion = certificateVersion;
        }

        public Duration getRefreshInterval() {
            return refreshInterval;
        }

        public void setRefreshInterval(Duration refreshInterval) {
            this.refreshInterval = refreshInterval;
        }

        public Duration getRetryInterval() {
            return retryInterval;
        }

        public void setRetryInterval(Duration retryInterval) {
            this.retryInterval = retryInterval;
        }

        public String getIdentityClientId() {
            return identityClientId;
        }

        public void setIdentityClientId(String identityClientId) {
            this.identityClientId = identityClientId;
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

        /**
         * Routes that pick the outbound client (and optionally the scope) per request, by URL pattern or host,
         * so one RestClient or WebClient can call several peers. The first matching route wins; requests that
         * match no route are sent without a token.
         */
        @Valid
        private List<OutboundRoute> routes = new ArrayList<>();

        /**
         * Hosts that never get a token from the routes, even when a route matches, for example
         * public.shop.svc.cluster.local or *.blob.core.windows.net. An optional :port restricts the port.
         */
        private List<String> skipHosts = new ArrayList<>();

        /**
         * Whether the routes are added to every RestClient.Builder and WebClient.Builder that Spring Boot
         * provides. Turn this off to apply them yourself with EntraOutboundClients#routingInterceptor().
         */
        private boolean customizeBuilders = true;

        public List<OutboundRoute> getRoutes() {
            return routes;
        }

        public void setRoutes(List<OutboundRoute> routes) {
            this.routes = routes;
        }

        public List<String> getSkipHosts() {
            return skipHosts;
        }

        public void setSkipHosts(List<String> skipHosts) {
            this.skipHosts = skipHosts;
        }

        public boolean isCustomizeBuilders() {
            return customizeBuilders;
        }

        public void setCustomizeBuilders(boolean customizeBuilders) {
            this.customizeBuilders = customizeBuilders;
        }

        void validate(Errors errors) {
            for (int i = 0; i < routes.size(); i++) {
                OutboundRoute route = routes.get(i);
                String field = "outbound.routes[" + i + "]";
                String key = PREFIX + "." + field;
                if (route.getClient() == null || route.getClient().isBlank()) {
                    errors.rejectValue(field + ".client", "missingRouteClient", key + ".client must name one of "
                            + "entra.security.outbound.clients " + clients.keySet());
                }
                else if (!clients.containsKey(route.getClient())) {
                    errors.rejectValue(field + ".client", "unknownRouteClient", key + ".client '"
                            + route.getClient() + "' is not configured under entra.security.outbound.clients "
                            + clients.keySet());
                }
                if (route.getUrls().isEmpty() && route.getHosts().isEmpty()) {
                    errors.rejectValue(field, "emptyRoute", key + " needs urls or hosts");
                }
                if (!route.getUrls().isEmpty() && !route.getPaths().isEmpty()) {
                    errors.rejectValue(field + ".paths", "pathsWithUrls", key + ".paths only applies to hosts; "
                            + "put the path into the url pattern instead");
                }
                try {
                    route.targets();
                }
                catch (IllegalArgumentException ex) {
                    errors.rejectValue(field, "invalidRoute", key + ": " + ex.getMessage());
                }
            }
            for (int i = 0; i < skipHosts.size(); i++) {
                try {
                    OutboundTarget.host(skipHosts.get(i), null, List.of());
                }
                catch (IllegalArgumentException | NullPointerException ex) {
                    errors.rejectValue("outbound.skipHosts", "invalidSkipHost",
                            PREFIX + ".outbound.skip-hosts[" + i + "]: " + ex.getMessage());
                }
            }
        }

        List<OutboundTarget> skipTargets() {
            return skipHosts.stream().map(host -> OutboundTarget.host(host, null, List.of())).toList();
        }
    }

    /** Maps outgoing requests to an outbound client by URL pattern or host. */
    public static class OutboundRoute {

        /** Optional name used in log messages. Defaults to the client name. */
        private String name;

        /**
         * URL patterns such as https://example.text.com/api/** or http://*.shop.svc.cluster.local/**. The
         * scheme is matched exactly, the host may start with *. and the path is an Ant-style pattern.
         */
        private List<String> urls = new ArrayList<>();

        /**
         * Host patterns such as orders.shop.svc.cluster.local, *.shop.svc.cluster.local or
         * partner.example.test:8443. https always matches; http only for *.svc, *.svc.cluster.local and
         * loopback hosts unless allow-http says otherwise.
         */
        private List<String> hosts = new ArrayList<>();

        /** Ant-style path patterns that restrict the hosts, for example /api/**. Empty matches every path. */
        private List<String> paths = new ArrayList<>();

        /** The outbound client (a key of entra.security.outbound.clients) whose credential and flow are used. */
        private String client;

        /** Optional scope for this route instead of the client's scope. */
        private String scope;

        /**
         * Whether hosts match over plain http. Unset allows http only for in-cluster and loopback hosts;
         * true is needed for other http hosts, false refuses http everywhere.
         */
        private Boolean allowHttp;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public List<String> getUrls() {
            return urls;
        }

        public void setUrls(List<String> urls) {
            this.urls = urls;
        }

        public List<String> getHosts() {
            return hosts;
        }

        public void setHosts(List<String> hosts) {
            this.hosts = hosts;
        }

        public List<String> getPaths() {
            return paths;
        }

        public void setPaths(List<String> paths) {
            this.paths = paths;
        }

        public String getClient() {
            return client;
        }

        public void setClient(String client) {
            this.client = client;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public Boolean getAllowHttp() {
            return allowHttp;
        }

        public void setAllowHttp(Boolean allowHttp) {
            this.allowHttp = allowHttp;
        }

        /** The name for log messages. */
        public String displayName() {
            return name != null && !name.isBlank() ? name : client;
        }

        /**
         * The parsed targets.
         *
         * @throws IllegalArgumentException when a pattern is invalid
         */
        public List<OutboundTarget> targets() {
            List<OutboundTarget> targets = new ArrayList<>();
            for (String url : urls) {
                if (url == null || url.isBlank()) {
                    throw new IllegalArgumentException("urls must not contain blank entries");
                }
                targets.add(OutboundTarget.url(url.trim()));
            }
            for (String host : hosts) {
                if (host == null || host.isBlank()) {
                    throw new IllegalArgumentException("hosts must not contain blank entries");
                }
                targets.add(OutboundTarget.host(host.trim(), allowHttp, paths));
            }
            return targets;
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

        /** Load the JWKS while the application starts, so the first request never waits for it. */
        private boolean jwksPrewarm = true;

        /**
         * Refresh the JWKS on a background thread during this window before {@code jwks-ttl} ends; zero refreshes
         * on the request that finds the keys expired. Capped at half of {@code jwks-ttl}.
         */
        @NotNull
        private Duration jwksRefreshAhead = Duration.ofMinutes(5);

        /**
         * How long a successfully validated token is remembered, so presenting it again skips the signature and
         * claim checks. Never past the token's {@code exp}. Zero disables the cache. Used in jwks mode only.
         */
        @NotNull
        private Duration validatedTokenTtl = Duration.ofMinutes(5);

        /** Maximum number of remembered validated tokens. */
        @Min(1)
        private int validatedTokenMaxEntries = 10_000;

        /**
         * How long the principal and role mapping of a token are remembered (including the Graph overage result).
         * Never past the token's {@code exp}. Zero disables the cache.
         */
        @NotNull
        private Duration authenticationTtl = Duration.ofMinutes(5);

        /** Maximum number of remembered role mappings. */
        @Min(1)
        private int authenticationMaxEntries = 10_000;

        /**
         * Renew outbound and Graph app tokens on a background thread once they enter the
         * {@code token-refresh-skew} window, instead of on the request that finds them stale.
         */
        private boolean tokenBackgroundRefresh = true;

        /**
         * Keep every Entra cache within its max entries under concurrency, and run one load per key.
         * Off by default, which keeps the previous cache.
         */
        private boolean bounded = false;

        public boolean isJwksPrewarm() {
            return jwksPrewarm;
        }

        public void setJwksPrewarm(boolean jwksPrewarm) {
            this.jwksPrewarm = jwksPrewarm;
        }

        public Duration getJwksRefreshAhead() {
            return jwksRefreshAhead;
        }

        public void setJwksRefreshAhead(Duration jwksRefreshAhead) {
            this.jwksRefreshAhead = jwksRefreshAhead;
        }

        public Duration getValidatedTokenTtl() {
            return validatedTokenTtl;
        }

        public void setValidatedTokenTtl(Duration validatedTokenTtl) {
            this.validatedTokenTtl = validatedTokenTtl;
        }

        public int getValidatedTokenMaxEntries() {
            return validatedTokenMaxEntries;
        }

        public void setValidatedTokenMaxEntries(int validatedTokenMaxEntries) {
            this.validatedTokenMaxEntries = validatedTokenMaxEntries;
        }

        public Duration getAuthenticationTtl() {
            return authenticationTtl;
        }

        public void setAuthenticationTtl(Duration authenticationTtl) {
            this.authenticationTtl = authenticationTtl;
        }

        public int getAuthenticationMaxEntries() {
            return authenticationMaxEntries;
        }

        public void setAuthenticationMaxEntries(int authenticationMaxEntries) {
            this.authenticationMaxEntries = authenticationMaxEntries;
        }

        public boolean isTokenBackgroundRefresh() {
            return tokenBackgroundRefresh;
        }

        public void setTokenBackgroundRefresh(boolean tokenBackgroundRefresh) {
            this.tokenBackgroundRefresh = tokenBackgroundRefresh;
        }

        public boolean isBounded() {
            return bounded;
        }

        public void setBounded(boolean bounded) {
            this.bounded = bounded;
        }

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
        private Duration connectTimeout = Duration.ofSeconds(2);

        /** Read timeout. */
        @NotNull
        private Duration readTimeout = Duration.ofSeconds(3);

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

    /** Thin Continuous Access Evaluation support. */
    public static class Cae {

        /**
         * Declare the {@code cp1} client capability on outbound token requests, answer a downstream
         * {@code insufficient_claims} challenge once with a fresh token, and render {@code ClaimsChallengeException}
         * as a claims challenge for callers whose token has {@code xms_cc=cp1}. The library never ends a session
         * on its own.
         */
        private boolean enabled = false;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /** The startup self-check. */
    public static class SelfCheck {

        /**
         * {@code warn} logs each problem, {@code fail} stops startup, {@code off} skips the check. Checks GUID
         * formats, that an audience is set, that the JWKS or introspection endpoint answers, and that outbound
         * clients have a credential.
         */
        private EntraStartupSelfCheck.Mode mode = EntraStartupSelfCheck.Mode.WARN;

        public EntraStartupSelfCheck.Mode getMode() {
            return mode;
        }

        public void setMode(EntraStartupSelfCheck.Mode mode) {
            this.mode = mode;
        }
    }

    /** Authorization shortcuts. */
    public static class Authorization {

        /**
         * Roles that open every authenticated API. Globs ({@code *hardware*}) or Java regular expressions prefixed
         * with {@code regex:}, matched against the whole mapped role name with or without {@code ROLE_}. A caller
         * with any matching role passes {@code @Secured}, {@code @PreAuthorize}, {@code @PostAuthorize} and
         * {@code @RolesAllowed}. Empty (off) by default; prefer explicit {@code @Secured} rules.
         */
        private List<String> allowRolePatterns = new ArrayList<>();

        /** Match {@code allow-role-patterns} case-sensitively. */
        private boolean allowRolePatternsCaseSensitive = false;

        public List<String> getAllowRolePatterns() {
            return allowRolePatterns;
        }

        public void setAllowRolePatterns(List<String> allowRolePatterns) {
            this.allowRolePatterns = allowRolePatterns;
        }

        public boolean isAllowRolePatternsCaseSensitive() {
            return allowRolePatternsCaseSensitive;
        }

        public void setAllowRolePatternsCaseSensitive(boolean allowRolePatternsCaseSensitive) {
            this.allowRolePatternsCaseSensitive = allowRolePatternsCaseSensitive;
        }
    }

    /** The audit line written for each auth decision. */
    public static class Audit {

        /** Write one log line per auth decision to the {@code entra.security.audit} logger at INFO. */
        private boolean enabled = true;

        /** {@code json} (one JSON object per line) or {@code flat} (one {@code key=value} line). */
        private AuditLogger.Format format = AuditLogger.Format.JSON;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public AuditLogger.Format getFormat() {
            return format;
        }

        public void setFormat(AuditLogger.Format format) {
            this.format = format;
        }
    }

    /** Auth timing and decision reporting. */
    public static class Observability {

        /**
         * Add {@code Server-Timing: auth;dur=<ms>} to every authenticated response. The authentication time is
         * always recorded as the {@code entra.security.auth.duration} timer; this switch only controls the
         * header.
         */
        private boolean serverTiming = true;

        public boolean isServerTiming() {
            return serverTiming;
        }

        public void setServerTiming(boolean serverTiming) {
            this.serverTiming = serverTiming;
        }
    }

    /** Metrics backend settings. Datadog is the documented default; Prometheus is opt-in. */
    public static class Monitoring {

        /** Extra tags added to every {@code entra.security.*} meter, e.g. {@code service=orders-api}. */
        private java.util.Map<String, String> tags = new java.util.LinkedHashMap<>();

        /** Datadog settings, applied only when micrometer-registry-datadog is on the classpath. */
        private final Datadog datadog = new Datadog();

        /** Prometheus settings, applied only when micrometer-registry-prometheus is on the classpath. */
        private final Prometheus prometheus = new Prometheus();

        public java.util.Map<String, String> getTags() {
            return tags;
        }

        public void setTags(java.util.Map<String, String> tags) {
            this.tags = tags;
        }

        public Datadog getDatadog() {
            return datadog;
        }

        public Prometheus getPrometheus() {
            return prometheus;
        }

        /** Datadog registry tuning. */
        public static class Datadog {

            /** Publish client-side p50/p95/p99 for entra.security timers (Datadog cannot aggregate histograms). */
            private boolean percentiles = true;

            public boolean isPercentiles() {
                return percentiles;
            }

            public void setPercentiles(boolean percentiles) {
                this.percentiles = percentiles;
            }
        }

        /** Prometheus registry tuning. */
        public static class Prometheus {

            /**
             * Export entra.security meters to Prometheus. Off by default: when false, the meters are
             * filtered out of a Prometheus registry even if one is present.
             */
            private boolean enabled = false;

            public boolean isEnabled() {
                return enabled;
            }

            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }
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
