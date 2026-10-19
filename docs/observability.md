# Observability and auth timing

Every API call that carries a bearer token (or is rejected for lacking one) gets its authentication work timed:
token validation, role mapping, the Graph overage lookup and authorization.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Start filter
    participant B as Bearer token filter
    participant A as Authorization
    participant E as End filter / 401-403 handler
    C->>S: request
    S->>B: start clock
    B->>A: validate + map roles (+ Graph)
    A->>E: allowed / denied
    E-->>C: Server-Timing: auth;dur=0.412
    E->>E: entra.security.auth.duration
```

| Output | Default | Switch |
|---|---|---|
| Micrometer timer `entra.security.auth.duration`, tags `outcome` (success, unauthenticated, forbidden, error), `token_type` (user, service, unknown, none), `validation_mode` (jwks, introspection, hybrid) | always on | - |
| `Server-Timing: auth;dur=<ms>` response header | on | `entra.security.observability.server-timing=false` |

Servlet and WebFlux behave the same. A method-security denial (`@Secured`) is recorded as `forbidden`. Public
paths called without a token are not recorded.

The timing hooks are part of `EntraHttpSecurity` / `EntraServerHttpSecurity`, so applications that build their own
filter chain with those helpers get them too.

## Audit line

One line per auth decision, written through SLF4J to the logger `entra.security.audit` at INFO, so it lands in
the normal application log / stdout. There is no Splunk- or Datadog-specific configuration: whatever ships your
logs ships these.

| Property | Default | Meaning |
|---|---|---|
| `entra.security.audit.enabled` | `true` | Turn the audit line off |
| `entra.security.audit.format` | `json` | `json` (one object per line) or `flat` (one `key=value` line) |

Fields: `ts`, `traceId` (MDC `traceId`/`correlationId`, else the W3C `traceparent` trace id, else
`X-Correlation-ID`/`X-Request-ID`, else generated), `outcome`, `reason`, `tokenType`, `validationMode`, `tid`,
`oid` (users) or `appid` (services), `roles`, `method`, `path` (no query string), `authMs`.

```json
{"ts":"2026-10-19T06:31:04.428Z","traceId":"4bf92f3577b34da6a3ce929d0e0e4736","outcome":"success","reason":"authorized","tokenType":"user","validationMode":"jwks","tid":"1111…","oid":"3333…","roles":["ROLE_ORDERS_READ"],"method":"GET","path":"/orders","authMs":1.932}
```

```text
ts=2026-10-19T06:31:04.433Z traceId=1039e7e0-… outcome=forbidden reason=access_denied tokenType=user validationMode=jwks tid=1111… oid=3333… roles=ROLE_ORDERS_READ method=GET path=/admin authMs=3.018
```

Tokens, names, UPNs and e-mail addresses are never logged. To silence or route the lines on their own, set
`logging.level.entra.security.audit=OFF` or give that logger its own appender.
