# Monitoring

Datadog is the supported backend. Prometheus and Grafana are optional and you have to opt in.

## Datadog (the default setup)

Add the registry. Spring Boot creates it, and the starter only tunes the `entra.security.*` meters.

```xml
<dependency>
  <groupId>io.micrometer</groupId>
  <artifactId>micrometer-registry-datadog</artifactId>
</dependency>
```

```yaml
management:
  datadog:
    metrics:
      export:
        api-key: ${DATADOG_API_KEY}     # from a Kubernetes Secret, never a ConfigMap
        step: 30s
        uri: https://api.datadoghq.eu   # pick your Datadog site
  metrics:
    tags:
      env: prod
entra:
  security:
    monitoring:
      tags:
        service: orders-api
```

```yaml
# Deployment excerpt
env:
  - name: DATADOG_API_KEY
    valueFrom:
      secretKeyRef: { name: datadog, key: api-key }
```

Datadog cannot aggregate Micrometer histograms, so by default the starter publishes client-side
p50/p95/p99 for the entra timers. To turn that off, set `entra.security.monitoring.datadog.percentiles=false`.

## Prometheus and Grafana (opt-in)

This applies only when `micrometer-registry-prometheus` is on the classpath **and**
`entra.security.monitoring.prometheus.enabled=true`. Otherwise the entra meters are filtered out of
any Prometheus registry. Expose `/actuator/prometheus` as usual. A sample dashboard is in
[grafana/entra-security-dashboard.json](grafana/entra-security-dashboard.json).

## Audit logs

Audit lines are not a metrics concern. They go to stdout through the `entra.security.audit` logger, as
`json` (the default) or `flat`, set with `entra.security.audit.format`. Whatever already ships your container
logs picks them up. The starter has no log-shipper-specific settings.

## Meters

| Meter | Type | Tags |
|---|---|---|
| `entra.security.auth.duration` | timer | outcome, token_type, validation_mode |
| `entra.security.jwt.authentications` | counter | result, reason |
| `entra.security.jwks.refreshes` | timer | result |
| `entra.security.token.acquisitions` | timer | result, credential, grant |
| `entra.security.graph.lookups` | timer | result |
| `entra.security.introspection.requests` | timer | result |

The starter has no multi-tenant dimensions and no per-endpoint rules.
