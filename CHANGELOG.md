# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Outbound routing: `entra.security.outbound.routes` maps URL patterns (`urls`) or hosts (`hosts` with
  `*.domain` wildcards, optional `:port` and Ant-style `paths`) to an outbound client, with an optional
  per-route `scope`. One `RestClient` or `WebClient` can then call external HTTPS APIs and in-cluster
  `*.svc.cluster.local` services, each with the right token. The first match wins. Requests that match no
  route, go to `outbound.skip-hosts` or already carry an `Authorization` header get no token. Plain http
  matches only in-cluster and loopback hosts unless `allow-http` is set. Spring Boot's `RestClient.Builder`
  and `WebClient.Builder` get the routes automatically (`outbound.customize-builders`, default `true`).
  `EntraOutboundClients#routingInterceptor()` and `EntraWebClientSupport#routingFilter(...)` cover
  hand-built clients. Routes are validated at startup.
- `docs/service-to-service.md`: inbound app-role mapping and outbound routing, with sequence diagrams.

- Optional remote token validation with `entra.security.validation.mode`: `jwks` (default, unchanged),
  `introspection` or `hybrid`. JWKS stays the recommended and fastest option for Entra ID tokens.
  - Microsoft Entra ID has no RFC 7662 introspection endpoint. `introspection.type=rfc7662` (the default)
    is meant for gateways and custom authorization servers. `introspection.type=userinfo` presents the
    token to a userinfo-style endpoint (Graph `/oidc/userinfo` by default, or `/v1.0/me`) for tokens whose
    audience is Microsoft Graph. That check proves who the user is, not that the token was issued for this
    API.
  - `hybrid-strategy=both` (default) validates with JWKS and then requires the remote check to report the
    token active, which catches revoked tokens. `fallback` validates JWTs with JWKS and sends only opaque
    tokens to the remote check. A JWT that fails JWKS validation is never retried remotely.
  - RFC 7662 settings: `introspection.uri` (defaults to the discovered `introspection_endpoint`),
    `auth-method` (`client-secret-basic`, `client-secret-post`, `bearer` with an app-only token for
    `introspection.scope`, or `none`), `client-id`, `client-secret`, `token-type-hint`, `validate-claims`
    (issuer, audience, tenant and time checks on the returned claims) and `claims-mapping`. By default
    `scope` is mapped to `scp` and `client_id` to `azp`. For userinfo, `id` is mapped to `oid`,
    `userPrincipalName` to `preferred_username` and `displayName` to `name`.
  - Active results are cached until min(`exp`, `positive-cache-ttl`, default `5m`), inactive results for
    `negative-cache-ttl` (default `10s`), with up to `cache-max-entries` entries keyed by a SHA-256 hash of
    the token. `connect-timeout` (`2s`) and `read-timeout` (`3s`) bound each call. After
    `failure-threshold` (5) consecutive failures a circuit breaker opens for `open-duration` (`30s`). While
    it is open, tokens that aren't cached are rejected with `401`, so the check fails closed.
  - Core: `TokenIntrospector`, `Rfc7662TokenIntrospector`, `UserInfoTokenIntrospector`,
    `CachingTokenIntrospector`, `IntrospectionCircuitBreaker`, `IntrospectionJwtDecoder` and
    `HybridJwtDecoder`. The starter exposes the check as a replaceable `TokenIntrospector` bean.
  - Metric `entra.security.introspection.requests` (timer, tag `result`: `active`, `inactive`, `error`,
    `rejected`). The JWKS health indicator and the JWKS preload are skipped in `introspection` mode.
- `TtlCache.put(key, value, ttl)` for per-entry lifetimes.

- Custom tenant and authority endpoints under `entra.security.authority.*`, all optional and bindable from a
  ConfigMap or environment variables: `host` (sovereign clouds, B2C, CIAM, custom domains), `tenant-path`
  (for example `contoso.onmicrosoft.com/B2C_1_signin`), `issuers`, `jwks-uri`, `token-endpoint`,
  `authorize-endpoint`, `metadata-uri`, `userinfo-endpoint`, `graph-base-url` and `allow-http`.
  - `authority.discovery.enabled` (or setting `metadata-uri`) fills every endpoint that is not configured from
    the OIDC discovery document at startup. `authority.discovery.required` (default `true`) decides whether a
    failed fetch stops startup or falls back to the defaults.
  - Explicit values win over discovered ones, and `authority.*` wins over the older top-level `authority-host`,
    `jwk-set-uri` and `issuers`, which keep working. With nothing set the endpoints are unchanged.
  - URLs are validated at startup: absolute, `https` (plain `http` only on loopback or with
    `authority.allow-http=true`), and a tenant path without `..`, `?` or `#`. Discovered URLs get the same checks.
  - `EntraEndpoints` bean with the resolved values, used by the decoder, JWKS source, token providers, Graph
    lookups and the Graph health indicator.
- `EntraMockAuthority.start(String publicHost)` serves the mock authority under a custom host name. Its
  discovery document now also lists `authorization_endpoint`.

### Changed

- Tests resolve host names through a test-only hosts file (`-Djdk.net.hosts.file`) in the starter and test
  modules, so custom authority and service host names reach local mocks and nothing reaches the network.

## [0.6.0] - 2026-10-18

### Added

- Compact role mappings for environment variables and ConfigMap scalars:
  `group-role-mappings-compact`, `app-role-mappings-compact` and `client-role-mappings-compact`
  (for example `ENTRA_SECURITY_GROUPROLEMAPPINGSCOMPACT="<guid>=ADMIN|READER;<guid>=READER"`).
  - Entries are separated by `;` or `,`. Roles within an entry are separated by `|`, and a repeated key
    adds roles.
  - They are merged with the map form, with keys compared case-insensitively.
  - Malformed values stop startup with a message naming the property, the entry number and the problem.
    App role keys must not contain whitespace and client ids must be GUIDs.
  - `CompactRoleMappings` (core) does the parsing and merging for applications that don't use Spring
    Boot.
- Encrypted PEM private keys: `credential.type=certificate` accepts PKCS#8 `ENCRYPTED PRIVATE KEY` blocks,
  decrypted with `credential.certificate-password`. This covers PBES2, which is what OpenSSL writes, and
  the PBES1 schemes the JDK supports. `ClientCertificateCredential.fromPem(pem, password)` is the core
  equivalent.
- Azure Key Vault certificate credentials: `credential.type=key-vault-certificate` with
  `credential.key-vault.vault-url`, `certificate-name` and optional `certificate-version`,
  `refresh-interval` (default `1h`), `retry-interval` (default `1m`) and `identity-client-id`.
  - The vault is read with `DefaultAzureCredential` (workload identity on AKS, managed identity
    elsewhere). A `TokenCredential` bean named `entraKeyVaultTokenCredential` replaces it.
  - The private key is read through `azure-security-keyvault-secrets`, or through
    `azure-security-keyvault-certificates` when only that library is present. PKCS#12 and PEM content
    types are both supported.
  - `RefreshingCertificateCredential` (core) caches the certificate and reloads it in the background of
    token requests. A failed reload keeps the cached certificate and retries after `retry-interval`.
  - Auto-configured by `EntraKeyVaultAutoConfiguration` only when `azure-identity` and one of the Key Vault
    libraries are on the classpath. All three are optional dependencies of the starter. Configuring the
    type without them fails startup and names the dependencies to add.
- Dependabot for Maven dependencies and GitHub Actions (weekly; Spring Boot major upgrades excluded).
- CodeQL analysis for Java on pull requests, pushes to `main` and a weekly schedule.
- JaCoCo coverage reports in every module, a line and branch minimum per library module enforced by
  `mvn verify`, and a coverage summary and report artifact in CI.
- `SECURITY.md`, `CONTRIBUTING.md`, and issue and pull request templates.

### Changed

- `EntraAuthorityMapper` is built from `EntraSecurityProperties.resolveGroupRoleMappings()`,
  `resolveAppRoleMappings()` and `resolveClientRoleMappings()`, which combine the map and compact forms.
- `EntraTokenProviders` has a constructor that takes a `KeyVaultCredentialFactory`. The existing
  constructors are unchanged.
- The parent POM imports `com.azure:azure-sdk-bom` 1.3.9.

## [0.5.0] - 2026-10-18

### Added

- On-behalf-of (OBO) flow for calling downstream APIs as the signed-in user:
  - `OnBehalfOfTokenProvider` (core): exchanges the incoming user token with Entra's
    `urn:ietf:params:oauth:grant-type:jwt-bearer` grant (`requested_token_use=on_behalf_of`), authenticated with
    the configured credential: client secret, certificate or workload identity.
  - Tokens are cached per user and scope under a SHA-256 hash of `oid` (or `sub`), `tid` and the normalized
    scope, renewed `cache.token-refresh-skew` before expiry, and bounded by `cache.on-behalf-of-max-entries`
    (default 10000). A failed renewal keeps using the cached token until it expires, unless Entra asks for a
    user interaction.
  - App-only callers are refused before any request is sent.
  - `EntraInteractionRequiredException` for missing consent (`AADSTS65001`, `consent_required`) and
    Conditional Access or MFA challenges (`interaction_required`, claims challenge), with the scope, `suberror`,
    `AADSTS` codes and claims.
  - Outbound helpers: `EntraOnBehalfOfInterceptor` for `RestClient`/`RestTemplate` (user from the
    `SecurityContextHolder`) and `EntraOnBehalfOfExchangeFilterFunction` for `WebClient` (user from the Reactor
    context, or the subscribing thread in servlet applications). `EntraUserTokens` finds the current user token.
  - `entra.security.outbound.clients.<name>.flow=on-behalf-of`: `EntraOutboundClients.interceptor(...)`,
    `EntraWebClientSupport.filter(...)` and `token(...)` follow the configured flow; `token(name, jwt)` and
    `onBehalfOfTokenProvider(name)` for explicit use.
  - `InteractionRequiredExceptionHandler` (Spring MVC) and `ServerInteractionRequiredExceptionHandler` (WebFlux),
    auto-configured: a 403 `application/problem+json` response with `error` `consent_required` or
    `interaction_required`, the `scope` and `claims`, and a matching `WWW-Authenticate` header.
- `entra-security-test`: the mock token endpoint serves the on-behalf-of grant (assertion signature, expiry,
  audience and user-token checks, delegated token for the same user), with `requireConsent(...)`,
  `requireInteraction(...)`, `onBehalfOfTokenLifetime(...)`, `onBehalfOfRequests()` and
  `onBehalfOfRequestForms()`.
- README section "Calling APIs as the user (on-behalf-of)" and on-behalf-of testing notes.

### Changed

- `entra.security.token.acquisitions` has a `grant` tag (`client_credentials` or `on_behalf_of`).
  `EntraSecurityObservations` gained `tokenAcquisition(grant, credentialType, success, duration)`; its default
  forwards client-credentials calls to the existing method, so custom implementations keep working.
- Client-credentials and on-behalf-of requests share one token-endpoint client; error messages are unchanged.

## [0.4.0] - 2026-10-18

### Added

- Reactive (WebFlux) resource-server support, auto-configured only in reactive web applications
  (`EntraReactiveSecurityAutoConfiguration`). Servlet applications are unchanged.
  - `EntraReactiveJwtDecoder`: runs the same decoder as the servlet stack (RS256, tenant JWKS cache, issuer,
    audience, tenant, `exp`/`nbf` with clock skew) on `boundedElastic`, so both stacks accept and reject the
    same tokens with the same errors.
  - `ReactiveEntraJwtAuthenticationConverter`: the same user/service classification, group, app-role and
    client mappings and client allow-list as `EntraJwtAuthenticationConverter`.
  - Group overage through `ReactiveGraphGroupMembershipResolver` (`WebClient`, same request, paging limit and
    errors as the blocking resolver) and `CachingReactiveGroupMembershipResolver`; failed lookups fail closed
    and are not cached. An application-defined blocking `GroupMembershipResolver` is adapted onto
    `boundedElastic`.
  - JSON 401/403: `ServerProblemDetailsAuthenticationEntryPoint` and `ServerProblemDetailsAccessDeniedHandler`
    write the same status, `WWW-Authenticate` header and `application/problem+json` body as the servlet
    handlers.
  - Default `SecurityWebFilterChain` (`entraSecurityWebFilterChain`): stateless, CSRF off, public paths open,
    everything else authenticated. Backs off when the application defines its own; `EntraServerHttpSecurity`
    applies the same setup to a custom chain.
  - Method security: `@EnableReactiveMethodSecurity` by default (`entra.security.method-security.enabled`),
    plus `@Secured` for reactive methods, which Spring Security does not provide on WebFlux. `@Secured` is also
    added when the application enables `@EnableReactiveMethodSecurity` itself.
  - `EntraPrincipal` and `Mono<EntraPrincipal>` controller parameters, and `ReactiveEntraPrincipals.current()`.
- `entra-security-test`: `EntraWebTestClient.bearer(...)`, and `@WithMockEntraUser`/`@WithMockEntraService`
  go through the reactive converter in WebFlux applications.
- `sample-reactive-api`: the sample service on WebFlux with no servlet API on the classpath, tested with
  `WebTestClient` against the mock authority, including a real Netty server.
- README section "Reactive (WebFlux)" and WebTestClient testing notes.

### Changed

- `@EnableEntraSecurity` picks the method security for the application type: `@EnableMethodSecurity`
  (`@Secured`, `@PreAuthorize`, `@RolesAllowed`) for servlet and non-web applications,
  `@EnableReactiveMethodSecurity` with `@Secured` for WebFlux. `mode` and `proxyTargetClass` still apply.
- The servlet-only beans of `EntraSecurityAutoConfiguration` (`JwtDecoder`, `EntraJwtAuthenticationConverter`,
  `GroupMembershipResolver`, problem-details handlers, `EntraHttpSecurity`, method security) are no longer
  created in reactive web applications. The shared beans (properties, JWKS source, token providers, classifier,
  authority mapper) are unchanged.
- `TtlCache` gained `getIfPresent` and `put`.

## [0.3.0] - 2026-10-18

### Added

- Actuator health indicators, registered only when `spring-boot-actuator` is on the classpath:
  - `entraJwks`: UP when the tenant JWKS can be fetched or read from cache and has at least one RSA
    signing key; DOWN when it cannot be loaded or has no usable key.
  - `entraGraph`: registered when `entra.security.graph.overage-enabled=true`. UP when an app-only
    token can be acquired and `GET {graph.base-url}/v1.0/` succeeds; DOWN when the credential or Graph
    is unavailable. Omitted when overage is disabled, so it does not fail health.
- Micrometer meters under `entra.security.*`, registered only when `micrometer-core` is on the classpath:
  JWT authentication outcomes, JWKS refreshes, Graph group-overage lookups and client-credentials token
  acquisition. Tag values are a fixed set (no object id, token or group id). Cache hits are not counted.
- `EntraMockAuthority` serves `GET /v1.0/` for the Graph health probe (bearer token required).

## [0.2.0] - 2026-10-17

### Added

- `entra-security-test` module for consuming services (use with `<scope>test</scope>`):
  - `EntraMockAuthority`: an in-process authority on a random loopback port serving the JWKS, a discovery
    document, client-credentials tokens and Microsoft Graph `transitiveMemberOf` for any tenant, with request
    counters for assertions.
  - `EntraTestTokens`: signed v2 and v1 user and service tokens with a fluent builder (groups, app roles,
    scopes, group overage, expiry, wrong audience, issuer or tenant, unknown key, HS256).
  - `@AutoConfigureEntraMockAuthority`: points a Spring test context at a shared mock authority and registers
    `EntraTestTokens` bound to the context's tenant and client id.
  - `@WithMockEntraUser` and `@WithMockEntraService`: run a test as a user or service with no token, through
    the real role mapping when the starter is present.
  - `EntraMockMvc.bearer(...)` request post-processor.
- README section "Testing your service".

### Changed

- `sample-api` tests use `entra-security-test` instead of hand-rolled WireMock stubs.

## [0.1.0] - 2026-10-17

### Added

- Multi-module build: `entra-security-core`, `entra-security-spring-boot-starter` and `sample-api`.
- Auto-configuration (`AutoConfiguration.imports`) that makes a servlet Spring Boot 3.x app an Entra ID
  resource server with no security code: stateless, CSRF off, public paths, JSON problem details
  (RFC 9457) for 401 and 403.
- `@EnableEntraSecurity`: turns on method security (`@Secured`, `@PreAuthorize`, `@RolesAllowed`) and
  preloads the tenant signing keys at startup, optionally failing startup if they cannot be fetched.
- Token validation: RS256 only, tenant JWKS with caching, v1 and v2 issuers, `api://<clientId>` and
  `<clientId>` audiences, `tid` check, required `exp`/`iss`/`aud`, configurable clock skew.
- User flow: `groups` claim (ids or names) → roles through `group-role-mappings`; optional `roles`
  claim (enterprise-app assignments) and `scp` → `SCOPE_x`; group overage (`_claim_names`/`hasgroups`)
  resolved through Microsoft Graph `transitiveMemberOf` with client credentials, cached per user,
  failing closed.
- Service flow: app-only tokens detected by `idtyp` or missing `scp`; `roles` → roles through
  `app-role-mappings`; `azp`/`appid` → roles through `client-role-mappings`, optional strict allow-list.
- `EntraPrincipal` (user or service, oid, appid, roles, groups, scopes), injectable as a controller
  parameter, with `@AuthenticationPrincipal`, or through `EntraPrincipals.current()`.
- Outbound calls: `EntraOutboundClients` with a `RestClient` interceptor and a `WebClient` filter; token
  acquisition by client secret, certificate (PEM or PKCS#12, signed client assertion) or Azure Workload
  Identity (federated token file), with per-scope caching.
- `entra.security.*` configuration validated at startup with clear messages; works from YAML, a mounted
  ConfigMap, a configtree Secret, env vars or `SPRING_APPLICATION_JSON`.
- Privacy-safe DEBUG claim logging.
- Tests against locally generated RSA keys and WireMock (JWKS, token endpoint, Graph); GitHub Actions on
  Java 17 and 21.

[Unreleased]: https://github.com/rmkr-dev/spring-security-jwt-starter/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/rmkr-dev/spring-security-jwt-starter/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/rmkr-dev/spring-security-jwt-starter/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/rmkr-dev/spring-security-jwt-starter/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/rmkr-dev/spring-security-jwt-starter/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rmkr-dev/spring-security-jwt-starter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rmkr-dev/spring-security-jwt-starter/releases/tag/v0.1.0
