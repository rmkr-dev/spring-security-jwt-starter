package io.github.rmkrdev.entra.security.core.jwt;

import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.JwtValidationException;

/**
 * Bounded reasons for {@code entra.security.jwt.authentications}. The set is fixed so metric tags
 * cannot grow with token contents, object ids or exception text.
 */
public final class JwtAuthenticationOutcomes {

    public static final String NONE = "none";
    public static final String MISSING = "missing";
    public static final String EXPIRED = "expired";
    public static final String NOT_YET_VALID = "not_yet_valid";
    public static final String INVALID_ISSUER = "invalid_issuer";
    public static final String INVALID_AUDIENCE = "invalid_audience";
    public static final String INVALID_TENANT = "invalid_tenant";
    public static final String MISSING_CLAIMS = "missing_claims";
    public static final String INVALID_SIGNATURE = "invalid_signature";
    public static final String UNKNOWN_KEY = "unknown_key";
    public static final String MALFORMED = "malformed";
    public static final String CLIENT_NOT_ALLOWED = "client_not_allowed";
    public static final String NOT_ACCESS_TOKEN = "not_access_token";
    public static final String INVALID_TOKEN = "invalid_token";

    private static final Set<String> REASONS = Set.of(NONE, MISSING, EXPIRED, NOT_YET_VALID, INVALID_ISSUER,
            INVALID_AUDIENCE, INVALID_TENANT, MISSING_CLAIMS, INVALID_SIGNATURE, UNKNOWN_KEY, MALFORMED,
            CLIENT_NOT_ALLOWED, NOT_ACCESS_TOKEN, INVALID_TOKEN);

    private JwtAuthenticationOutcomes() {
    }

    /**
     * Maps a validation or authentication failure onto {@link #REASONS}. Anything unrecognized becomes
     * {@link #INVALID_TOKEN}.
     */
    public static String reason(Throwable error) {
        String text = describe(error);
        if (text.contains("calling client application is not allowed")) {
            return CLIENT_NOT_ALLOWED;
        }
        if (text.contains(EntraAccessTokenValidator.DESCRIPTION)) {
            return NOT_ACCESS_TOKEN;
        }
        if (text.contains("Jwt expired")) {
            return EXPIRED;
        }
        if (text.contains("used before") || text.contains("not valid before")) {
            return NOT_YET_VALID;
        }
        if (text.contains("iss claim")) {
            return INVALID_ISSUER;
        }
        if (text.contains("aud claim")) {
            return INVALID_AUDIENCE;
        }
        if (text.contains("tid claim")) {
            return INVALID_TENANT;
        }
        if (text.contains("claim is required")) {
            return MISSING_CLAIMS;
        }
        if (text.contains("Invalid signature")) {
            return INVALID_SIGNATURE;
        }
        if (text.contains("no matching key") || text.contains("Another algorithm")) {
            return UNKNOWN_KEY;
        }
        if (text.contains("Malformed") || text.contains("Invalid serialized")
                || text.contains("Invalid unsecured") || text.contains("Invalid JWT")) {
            return MALFORMED;
        }
        return INVALID_TOKEN;
    }

    /**
     * {@code true} when {@code reason} is one of the fixed labels.
     */
    public static boolean isKnown(String reason) {
        return REASONS.contains(reason);
    }

    private static String describe(Throwable error) {
        StringBuilder text = new StringBuilder();
        Throwable current = error;
        for (int depth = 0; current != null && depth < 8; depth++) {
            if (current.getMessage() != null) {
                text.append(current.getMessage()).append('\n');
            }
            if (current instanceof JwtValidationException validation) {
                for (OAuth2Error oauthError : validation.getErrors()) {
                    if (oauthError.getDescription() != null) {
                        text.append(oauthError.getDescription()).append('\n');
                    }
                }
            }
            current = current.getCause();
        }
        return text.toString();
    }
}
