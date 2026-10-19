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
