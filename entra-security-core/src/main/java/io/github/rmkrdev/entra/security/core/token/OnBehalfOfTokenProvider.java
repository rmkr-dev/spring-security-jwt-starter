package io.github.rmkrdev.entra.security.core.token;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

import io.github.rmkrdev.entra.security.core.jwt.EntraClaimNames;
import io.github.rmkrdev.entra.security.core.jwt.EntraTokenClassifier;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

/**
 * Acquires downstream tokens with the on-behalf-of flow against the Entra v2 token endpoint:
 * {@code grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer}, the incoming user token as
 * {@code assertion} and {@code requested_token_use=on_behalf_of}, authenticated with this API's
 * {@link EntraCredential} (client secret, certificate or workload identity).
 * <p>
 * Tokens are cached per user and scope. The cache key is a SHA-256 hash of the user's {@code oid}
 * (or {@code sub}), {@code tid} and the normalized scope, so neither the incoming token nor user
 * identifiers are kept as keys. A cached token is renewed {@code refreshSkew} before it expires (at
 * most halfway through its lifetime); if the renewal fails for a reason other than a required user
 * interaction while the cached token is still valid, the cached token is used and a warning is logged.
 * <p>
 * Only delegated user tokens can be exchanged: app-only tokens are refused before any call to Entra.
 */
public final class OnBehalfOfTokenProvider implements EntraOnBehalfOfTokenProvider {

    /** The OAuth 2.0 JWT bearer grant used for on-behalf-of. */
    public static final String GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private static final Logger log = LoggerFactory.getLogger(OnBehalfOfTokenProvider.class);
    private static final Set<String> INTERACTION_ERRORS = Set.of("interaction_required", "consent_required",
            "login_required");
    private static final Set<String> INTERACTION_SUBERRORS = Set.of("consent_required", "basic_action",
            "additional_action", "message_only");
    /** consent missing, MFA required, MFA registration required, external security challenge, CA policy. */
    private static final Set<Integer> INTERACTION_CODES = Set.of(65001, 65004, 50076, 50079, 50158, 53003);
    private static final int LOCK_STRIPES = 64;

    private final URI tokenEndpoint;
    private final String clientId;
    private final EntraCredential credential;
    private final TokenEndpointClient endpoint;
    private final Duration refreshSkew;
    private final Clock clock;
    private final int maxEntries;
    private final EntraSecurityObservations observations;
    private final EntraTokenClassifier classifier = new EntraTokenClassifier();
    private final Map<String, CachedToken> cache = new ConcurrentHashMap<>();
    private final Object[] locks = new Object[LOCK_STRIPES];

    /**
     * @param tokenEndpoint the token endpoint, see {@link ClientCredentialsTokenProvider#tokenEndpoint(URI, String)}
     * @param clientId      this API's client (application) id; the audience of the incoming tokens
     * @param credential    how this API authenticates
     * @param restClient    HTTP client
     * @param refreshSkew   how long before expiry a cached token is renewed
     * @param maxEntries    upper bound on cached tokens (users × scopes)
     * @param clock         time source
     * @param observations  notified on token-endpoint calls only; {@code null} is a no-op
     */
    public OnBehalfOfTokenProvider(URI tokenEndpoint, String clientId, EntraCredential credential,
            RestClient restClient, Duration refreshSkew, int maxEntries, Clock clock,
            EntraSecurityObservations observations) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be at least 1");
        }
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.credential = credential;
        this.endpoint = new TokenEndpointClient(tokenEndpoint, clientId, restClient, clock);
        this.refreshSkew = refreshSkew;
        this.maxEntries = maxEntries;
        this.clock = clock;
        this.observations = observations == null ? EntraSecurityObservations.NO_OP : observations;
        Arrays.setAll(locks, i -> new Object());
    }

    @Override
    public AccessToken getToken(Jwt userToken, String scope) {
        String normalizedScope = normalizeScope(scope);
        requireDelegated(userToken);
        String key = cacheKey(userToken, normalizedScope);
        CachedToken cached = cache.get(key);
        if (cached != null && cached.isFresh(clock.instant())) {
            return cached.token();
        }
        synchronized (locks[Math.floorMod(key.hashCode(), LOCK_STRIPES)]) {
            cached = cache.get(key);
            Instant now = clock.instant();
            if (cached != null && cached.isFresh(now)) {
                return cached.token();
            }
            try {
                CachedToken fresh = fetch(userToken, normalizedScope);
                store(key, fresh);
                return fresh.token();
            }
            catch (EntraInteractionRequiredException ex) {
                cache.remove(key);
                throw ex;
            }
            catch (EntraTokenAcquisitionException ex) {
                if (cached != null && cached.isUsable(clock.instant())) {
                    log.warn("Renewing an on-behalf-of token failed ({}); using the cached token until it expires "
                            + "at {}", ex.getMessage(), cached.token().expiresAt());
                    return cached.token();
                }
                throw ex;
            }
        }
    }

    /** Drops the cached token of one user and scope. */
    public void invalidate(Jwt userToken, String scope) {
        cache.remove(cacheKey(userToken, normalizeScope(scope)));
    }

    /** Drops every cached token. */
    public void invalidateAll() {
        cache.clear();
    }

    /** Number of cached tokens. */
    public int size() {
        return cache.size();
    }

    public String getClientId() {
        return clientId;
    }

    public URI getTokenEndpoint() {
        return tokenEndpoint;
    }

    /**
     * The cache key for a user and scope: base64url(SHA-256(oid or sub, tid, normalized scope)).
     */
    public static String cacheKey(Jwt userToken, String scope) {
        String user = userToken.getClaimAsString(EntraClaimNames.OBJECT_ID);
        if (!StringUtils.hasText(user)) {
            user = userToken.getSubject();
        }
        if (!StringUtils.hasText(user)) {
            throw new EntraTokenAcquisitionException("On-behalf-of needs a user token with an oid or sub claim",
                    "invalid_request", null);
        }
        String tenant = userToken.getClaimAsString(EntraClaimNames.TENANT_ID);
        String material = user.toLowerCase(Locale.ROOT) + '\n' + (tenant == null ? "" : tenant.toLowerCase(Locale.ROOT))
                + '\n' + normalizeScope(scope);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(material.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    /** Scopes split on whitespace, de-duplicated, sorted and joined with a single space. */
    static String normalizeScope(String scope) {
        if (!StringUtils.hasText(scope)) {
            throw new IllegalArgumentException("scope must not be empty");
        }
        return Arrays.stream(scope.trim().split("\\s+")).distinct().sorted().collect(Collectors.joining(" "));
    }

    private void requireDelegated(Jwt userToken) {
        if (userToken == null) {
            throw new EntraTokenAcquisitionException("On-behalf-of needs the caller's access token, but there is "
                    + "none", "invalid_request", null);
        }
        if (classifier.classify(userToken) != PrincipalType.USER) {
            throw new EntraTokenAcquisitionException("On-behalf-of needs a delegated user token; the caller "
                    + "authenticated with an app-only token. Use a client-credentials outbound client for "
                    + "service callers", "invalid_request", null);
        }
    }

    private CachedToken fetch(Jwt userToken, String scope) {
        long start = System.nanoTime();
        try {
            CachedToken fresh = requestToken(userToken, scope);
            observations.tokenAcquisition(EntraSecurityObservations.GRANT_ON_BEHALF_OF, credential.credentialType(),
                    true, Duration.ofNanos(System.nanoTime() - start));
            return fresh;
        }
        catch (RuntimeException ex) {
            observations.tokenAcquisition(EntraSecurityObservations.GRANT_ON_BEHALF_OF, credential.credentialType(),
                    false, Duration.ofNanos(System.nanoTime() - start));
            throw ex;
        }
    }

    private CachedToken requestToken(Jwt userToken, String scope) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", GRANT_TYPE_JWT_BEARER);
        form.add("client_id", clientId);
        form.add("assertion", userToken.getTokenValue());
        form.add("scope", scope);
        form.add("requested_token_use", "on_behalf_of");
        credential.contribute(form, tokenEndpoint, clientId);
        TokenEndpointClient.IssuedToken issued = endpoint.request(form, error -> toException(error, scope));
        return new CachedToken(issued.token(), TokenEndpointClient.refreshAt(issued, refreshSkew));
    }

    private EntraTokenAcquisitionException toException(TokenEndpointClient.TokenError error, String scope) {
        boolean interaction = (error.error() != null && INTERACTION_ERRORS.contains(error.error()))
                || (error.suberror() != null && INTERACTION_SUBERRORS.contains(error.suberror()))
                || StringUtils.hasText(error.claims())
                || error.errorCodes().stream().anyMatch(INTERACTION_CODES::contains);
        String message = endpoint.message("On-behalf-of token request", error);
        if (interaction) {
            EntraInteractionRequiredException ex = new EntraInteractionRequiredException(message, error.error(),
                    error.suberror(), scope, StringUtils.hasText(error.claims()) ? error.claims() : null,
                    error.errorCodes());
            String hint = ex.isConsentRequired()
                    ? " (the user or an administrator has to consent to '" + scope + "' for client " + clientId + ")"
                    : " (the user has to sign in again interactively, for example for MFA or Conditional Access)";
            return new EntraInteractionRequiredException(message + hint, error.error(), error.suberror(), scope,
                    ex.getClaims(), error.errorCodes());
        }
        return new EntraTokenAcquisitionException(message, error.error(), null);
    }

    private void store(String key, CachedToken token) {
        if (cache.size() >= maxEntries && !cache.containsKey(key)) {
            Instant now = clock.instant();
            cache.values().removeIf(entry -> !entry.isUsable(now));
            Iterator<String> keys = cache.keySet().iterator();
            while (cache.size() >= maxEntries && keys.hasNext()) {
                keys.next();
                keys.remove();
            }
        }
        cache.put(key, token);
    }

    private record CachedToken(AccessToken token, Instant refreshAt) {

        boolean isFresh(Instant now) {
            return now.isBefore(refreshAt);
        }

        boolean isUsable(Instant now) {
            return now.isBefore(token.expiresAt());
        }
    }
}
