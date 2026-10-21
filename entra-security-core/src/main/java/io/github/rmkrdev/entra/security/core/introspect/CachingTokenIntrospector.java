package io.github.rmkrdev.entra.security.core.introspect;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import io.github.rmkrdev.entra.security.core.cache.TtlCache;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;

/**
 * Caches remote token checks and guards them with a circuit breaker.
 * <ul>
 * <li>Active results are kept until the token expires or {@code positiveTtl} passes, whichever is first. The
 * expiry is the {@code exp} the authority returned, or else the {@code exp} read (unverified) from a JWT-shaped
 * token. That value only bounds the cache; it is never used for authorization.</li>
 * <li>Inactive results are kept for {@code negativeTtl}, so a replayed bad token does not reach the authority on
 * every request.</li>
 * <li>Failures are not cached. They count towards the circuit breaker, and while it is open tokens that are not
 * cached are rejected without a call (fail closed).</li>
 * </ul>
 * Cache keys are SHA-256 hashes of the token; tokens themselves are not kept as keys.
 */
public final class CachingTokenIntrospector implements TokenIntrospector {

    /** {@code result} label: the authority answered active. */
    public static final String ACTIVE = "active";
    /** {@code result} label: the authority answered inactive. */
    public static final String INACTIVE = "inactive";
    /** {@code result} label: the call failed. */
    public static final String ERROR = "error";
    /** {@code result} label: refused because the circuit is open. */
    public static final String REJECTED = "rejected";

    private final TokenIntrospector delegate;
    private final Duration positiveTtl;
    private final Duration negativeTtl;
    private final TtlCache<String, IntrospectionResult> cache;
    private final IntrospectionCircuitBreaker breaker;
    private final Clock clock;
    private final EntraSecurityObservations observations;

    public CachingTokenIntrospector(TokenIntrospector delegate, Duration positiveTtl, Duration negativeTtl,
            int maxEntries, IntrospectionCircuitBreaker breaker, Clock clock, EntraSecurityObservations observations) {
        this(delegate, positiveTtl, negativeTtl, maxEntries, breaker, clock, observations, false);
    }

    /**
     * @param bounded when {@code true}, one remote check runs per token and the cache stays within
     *                {@code maxEntries}
     */
    public CachingTokenIntrospector(TokenIntrospector delegate, Duration positiveTtl, Duration negativeTtl,
            int maxEntries, IntrospectionCircuitBreaker breaker, Clock clock, EntraSecurityObservations observations,
            boolean bounded) {
        this.delegate = delegate;
        this.positiveTtl = positiveTtl;
        this.negativeTtl = negativeTtl;
        this.cache = new TtlCache<>(positiveTtl.compareTo(negativeTtl) > 0 ? positiveTtl : negativeTtl, maxEntries,
                clock, bounded);
        this.breaker = breaker;
        this.clock = clock;
        this.observations = observations == null ? EntraSecurityObservations.NO_OP : observations;
    }

    @Override
    public IntrospectionResult introspect(String token) {
        String key = hash(token);
        if (cache.isBounded()) {
            IntrospectionResult cached = cache.getIfPresent(key);
            if (cached != null) {
                return cached;
            }
            return cache.coalesce(key, () -> fetch(token, key));
        }
        return fetch(token, key);
    }

    private IntrospectionResult fetch(String token, String key) {
        IntrospectionResult cached = cache.getIfPresent(key);
        if (cached != null) {
            return cached;
        }
        if (!breaker.tryAcquire()) {
            observations.introspection(REJECTED, Duration.ZERO);
            throw new IntrospectionException("Token introspection is unavailable: the circuit breaker is open after "
                    + "repeated failures", null);
        }
        long start = System.nanoTime();
        IntrospectionResult result;
        try {
            result = delegate.introspect(token);
        }
        catch (RuntimeException ex) {
            breaker.onFailure();
            observations.introspection(ERROR, Duration.ofNanos(System.nanoTime() - start));
            throw ex instanceof IntrospectionException introspection ? introspection
                    : new IntrospectionException("Token introspection failed: " + ex.getMessage(), ex);
        }
        breaker.onSuccess();
        observations.introspection(result.active() ? ACTIVE : INACTIVE, Duration.ofNanos(System.nanoTime() - start));
        Duration ttl = result.active() ? positiveTtl(token, result) : negativeTtl;
        if (!ttl.isNegative() && !ttl.isZero()) {
            cache.put(key, result, ttl);
        }
        return result;
    }

    /** The circuit breaker, for health and tests. */
    public IntrospectionCircuitBreaker circuitBreaker() {
        return breaker;
    }

    /** Number of cached results. */
    public int cachedResults() {
        return cache.size();
    }

    private Duration positiveTtl(String token, IntrospectionResult result) {
        Instant expiry = instant(result.claims().get("exp"));
        if (expiry == null) {
            expiry = unverifiedExpiry(token);
        }
        if (expiry == null) {
            return positiveTtl;
        }
        Duration untilExpiry = Duration.between(clock.instant(), expiry);
        return untilExpiry.compareTo(positiveTtl) < 0 ? untilExpiry : positiveTtl;
    }

    static Instant instant(Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof Date date) {
            return date.toInstant();
        }
        if (value instanceof Number number) {
            return Instant.ofEpochSecond(number.longValue());
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Instant.ofEpochSecond(Long.parseLong(text.trim()));
            }
            catch (NumberFormatException ex) {
                return null;
            }
        }
        return null;
    }

    private static Instant unverifiedExpiry(String token) {
        try {
            JWT jwt = JWTParser.parse(token);
            Date exp = jwt.getJWTClaimsSet().getExpirationTime();
            return exp == null ? null : exp.toInstant();
        }
        catch (java.text.ParseException | RuntimeException ex) {
            return null;
        }
    }

    static String hash(String token) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }
}
