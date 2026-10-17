package io.github.rmkrdev.entra.security.core.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;

import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;

/**
 * Logs a privacy-safe summary of an authenticated token at DEBUG level.
 * <p>
 * Never logs the raw token, names, usernames or e-mail addresses. Object ids are truncated.
 */
public final class SafeClaimLogger {

    private static final Logger log = LoggerFactory.getLogger(SafeClaimLogger.class);

    private final boolean enabled;

    public SafeClaimLogger(boolean enabled) {
        this.enabled = enabled;
    }

    public void log(Jwt jwt, EntraPrincipal principal) {
        if (!enabled || !log.isDebugEnabled()) {
            return;
        }
        log.debug("Entra token accepted: type={} oid={} appid={} tid={} ver={} iss={} roles={} groups={} scopes={}",
                principal.type(), mask(principal.objectId()), principal.appId(), principal.tenantId(),
                principal.tokenVersion(), jwt.getClaimAsString("iss"), principal.roles(),
                principal.groups().size(), principal.scopes());
    }

    static String mask(String value) {
        if (value == null) {
            return null;
        }
        return value.length() <= 8 ? "****" : value.substring(0, 8) + "****";
    }
}
