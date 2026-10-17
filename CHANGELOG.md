# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/rmkr-dev/spring-security-jwt-starter/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rmkr-dev/spring-security-jwt-starter/commits/main
