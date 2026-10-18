# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/rmkr-dev/spring-security-jwt-starter/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/rmkr-dev/spring-security-jwt-starter/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/rmkr-dev/spring-security-jwt-starter/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rmkr-dev/spring-security-jwt-starter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rmkr-dev/spring-security-jwt-starter/releases/tag/v0.1.0
