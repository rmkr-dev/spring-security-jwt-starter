package io.github.rmkrdev.entra.security.core.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import io.github.rmkrdev.entra.security.core.cache.TokenKeys;
import io.github.rmkrdev.entra.security.core.cache.TtlCache;
import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;

/**
 * The principal and authorities mapped for a token, so a token presented again skips classification, role
 * mapping and the Graph overage lookup. A new {@link EntraAuthenticationToken} is built for each request, so
 * per-request details never leak between requests.
 * <p>
 * Keyed by a SHA-256 hash of the token; entries live for {@code ttl} and never past the token's {@code exp}.
 * Results where the Graph lookup failed are not cached, so the next request tries again.
 */
public final class AuthenticationCache {

    private final TtlCache<String, Entry> cache;
    private final Clock clock;

    public AuthenticationCache(Duration ttl, int maxEntries, Clock clock) {
        this.cache = new TtlCache<>(ttl, maxEntries, clock);
        this.clock = clock;
    }

    /** A cached authentication for the token, or {@code null}. */
    public EntraAuthenticationToken get(Jwt jwt) {
        Entry entry = cache.getIfPresent(TokenKeys.of(jwt.getTokenValue()));
        return entry == null ? null : new EntraAuthenticationToken(jwt, entry.principal(), entry.authorities());
    }

    /** Remembers an authentication until min(ttl, exp). */
    public void put(Jwt jwt, EntraAuthenticationToken authentication) {
        Instant expiresAt = jwt.getExpiresAt();
        if (expiresAt == null) {
            return;
        }
        cache.put(TokenKeys.of(jwt.getTokenValue()),
                new Entry(authentication.getEntraPrincipal(), List.copyOf(authentication.getAuthorities())),
                Duration.between(clock.instant(), expiresAt));
    }

    public int size() {
        return cache.size();
    }

    private record Entry(EntraPrincipal principal, Collection<GrantedAuthority> authorities) {
    }
}
