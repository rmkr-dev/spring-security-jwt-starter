package io.github.rmkrdev.entra.security.autoconfigure.metrics;

import java.time.Duration;
import java.util.Set;

import io.github.rmkrdev.entra.security.core.jwt.JwtAuthenticationOutcomes;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

import io.github.rmkrdev.entra.security.core.decision.AuthDecision;

/**
 * Micrometer bindings for {@link EntraSecurityObservations}. Tag values are taken from a fixed set.
 */
final class MicrometerEntraSecurityObservations implements EntraSecurityObservations {

    static final String JWT_AUTHENTICATIONS = "entra.security.jwt.authentications";
    static final String GRAPH_LOOKUPS = "entra.security.graph.lookups";
    static final String TOKEN_ACQUISITIONS = "entra.security.token.acquisitions";
    static final String JWKS_REFRESHES = "entra.security.jwks.refreshes";
    static final String INTROSPECTIONS = "entra.security.introspection.requests";
    private static final Set<String> INTROSPECTION_RESULTS = Set.of("active", "inactive", "error", "rejected");

    private static final Set<String> CREDENTIALS = Set.of("client_secret", "certificate", "workload_identity");
    private static final Set<String> GRANTS = Set.of(GRANT_CLIENT_CREDENTIALS, GRANT_ON_BEHALF_OF);

    static final String AUTH_DURATION = "entra.security.auth.duration";
    private static final Set<String> AUTH_OUTCOMES = Set.of(AuthDecision.SUCCESS, AuthDecision.UNAUTHENTICATED,
            AuthDecision.FORBIDDEN, AuthDecision.ERROR);
    private static final Set<String> TOKEN_TYPES = Set.of("user", "service", "unknown", "none");
    private static final Set<String> MODES = Set.of("jwks", "introspection", "hybrid");

    private final MeterRegistry registry;

    MicrometerEntraSecurityObservations(MeterRegistry registry) {
        this.registry = registry;
    }

    @Override
    public void jwtAuthentication(boolean success, String reason) {
        registry.counter(JWT_AUTHENTICATIONS, "result", result(success), "reason", reason(reason)).increment();
    }

    @Override
    public void graphLookup(boolean success, Duration duration) {
        timer(GRAPH_LOOKUPS, "Microsoft Graph group-overage lookups", "result", result(success)).record(duration(duration));
    }

    @Override
    public void tokenAcquisition(String credentialType, boolean success, Duration duration) {
        tokenAcquisition(GRANT_CLIENT_CREDENTIALS, credentialType, success, duration);
    }

    @Override
    public void tokenAcquisition(String grant, String credentialType, boolean success, Duration duration) {
        timer(TOKEN_ACQUISITIONS, "Calls to the Entra token endpoint", "result", result(success),
                "credential", credential(credentialType), "grant", grant(grant)).record(duration(duration));
    }

    @Override
    public void authDecision(AuthDecision decision) {
        Timer.builder(AUTH_DURATION).description("Authentication work per API call: validation, role mapping, "
                + "Graph and authorization")
                .tags("outcome", bounded(decision.outcome(), AUTH_OUTCOMES, AuthDecision.ERROR),
                        "token_type", bounded(decision.tokenType(), TOKEN_TYPES, "unknown"),
                        "validation_mode", bounded(decision.validationMode(), MODES, "jwks"))
                .publishPercentileHistogram()
                .register(registry)
                .record(decision.duration());
    }

    private static String bounded(String value, Set<String> allowed, String fallback) {
        return allowed.contains(value) ? value : fallback;
    }

    @Override
    public void jwksRefresh(boolean success, Duration duration) {
        timer(JWKS_REFRESHES, "Fetches of the tenant JWKS document", "result", result(success))
                .record(duration(duration));
    }

    @Override
    public void introspection(String result, Duration duration) {
        timer(INTROSPECTIONS, "Remote token checks (introspection or userinfo)", "result",
                INTROSPECTION_RESULTS.contains(result) ? result : "error").record(duration(duration));
    }

    private Timer timer(String name, String description, String... tags) {
        return Timer.builder(name).description(description).tags(tags).register(registry);
    }

    private static String result(boolean success) {
        return success ? "success" : "failure";
    }

    private static String reason(String value) {
        return JwtAuthenticationOutcomes.isKnown(value) ? value : JwtAuthenticationOutcomes.INVALID_TOKEN;
    }

    private static String credential(String value) {
        return CREDENTIALS.contains(value) ? value : "unknown";
    }

    private static String grant(String value) {
        return GRANTS.contains(value) ? value : "unknown";
    }

    private static Duration duration(Duration value) {
        return value == null || value.isNegative() ? Duration.ZERO : value;
    }
}
