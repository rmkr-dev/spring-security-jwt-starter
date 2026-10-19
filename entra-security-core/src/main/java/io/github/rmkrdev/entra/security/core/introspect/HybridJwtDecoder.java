package io.github.rmkrdev.entra.security.core.introspect;

import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

/**
 * Local JWKS validation combined with a remote check.
 * <ul>
 * <li>{@link Strategy#BOTH}: the token must pass local validation first (signature, issuer, audience, expiry),
 * and then the remote check must report it active. This catches revoked tokens at the cost of a remote call per
 * token (cached).</li>
 * <li>{@link Strategy#FALLBACK}: signed JWTs are validated locally only; tokens that are not JWTs (opaque
 * tokens) go to the remote check. A JWT that fails local validation is rejected, never retried remotely.</li>
 * </ul>
 */
public final class HybridJwtDecoder implements JwtDecoder {

    /** How the two checks combine. */
    public enum Strategy {
        /** Local validation, then the remote check; both must pass. */
        BOTH,
        /** Local validation for JWTs, the remote check for opaque tokens. */
        FALLBACK
    }

    private final JwtDecoder local;
    private final TokenIntrospector remote;
    private final JwtDecoder remoteDecoder;
    private final Strategy strategy;

    /**
     * @param local         the JWKS decoder
     * @param remote        the remote check, used by {@link Strategy#BOTH}
     * @param remoteDecoder decodes opaque tokens remotely, used by {@link Strategy#FALLBACK}
     */
    public HybridJwtDecoder(JwtDecoder local, TokenIntrospector remote, JwtDecoder remoteDecoder, Strategy strategy) {
        this.local = local;
        this.remote = remote;
        this.remoteDecoder = remoteDecoder;
        this.strategy = strategy;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        if (strategy == Strategy.FALLBACK) {
            return isSignedJwt(token) ? local.decode(token) : remoteDecoder.decode(token);
        }
        Jwt jwt = local.decode(token);
        if (!IntrospectionJwtDecoder.check(remote, token).active()) {
            throw new BadJwtException("The token is no longer active");
        }
        return jwt;
    }

    public Strategy getStrategy() {
        return strategy;
    }

    private static boolean isSignedJwt(String token) {
        try {
            return token != null && JWTParser.parse(token) instanceof SignedJWT;
        }
        catch (java.text.ParseException ex) {
            return false;
        }
    }
}
