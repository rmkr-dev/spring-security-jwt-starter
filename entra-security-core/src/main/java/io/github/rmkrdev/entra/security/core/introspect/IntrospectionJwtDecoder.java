package io.github.rmkrdev.entra.security.core.introspect;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

/**
 * A {@link JwtDecoder} that validates tokens remotely instead of with signing keys, so the rest of the starter
 * (role mapping, {@code EntraPrincipal}, method security) works unchanged. The returned {@link Jwt} holds the
 * mapped claims from the authority, not the token's own payload, and has the header {@code alg=none},
 * {@code typ=introspected}.
 * <p>
 * Inactive tokens and failed checks are both rejected as invalid tokens ({@code 401}).
 */
public final class IntrospectionJwtDecoder implements JwtDecoder {

    private final TokenIntrospector introspector;
    private final IntrospectedClaimsMapper claimsMapper;
    private final OAuth2TokenValidator<Jwt> validator;

    /**
     * @param validator applied to the mapped claims, or {@code null} for none
     */
    public IntrospectionJwtDecoder(TokenIntrospector introspector, IntrospectedClaimsMapper claimsMapper,
            OAuth2TokenValidator<Jwt> validator) {
        this.introspector = introspector;
        this.claimsMapper = claimsMapper;
        this.validator = validator;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        if (token == null || token.isBlank()) {
            throw new BadJwtException("Empty bearer token");
        }
        IntrospectionResult result = check(introspector, token);
        if (!result.active()) {
            throw new BadJwtException("The token is not active");
        }
        Jwt jwt = toJwt(token, claimsMapper.map(result.claims()));
        if (validator != null) {
            OAuth2TokenValidatorResult validation = validator.validate(jwt);
            if (validation.hasErrors()) {
                throw new JwtValidationException("The introspected token failed validation: "
                        + validation.getErrors().iterator().next().getDescription(), validation.getErrors());
            }
        }
        return jwt;
    }

    /** Runs the check and turns an unavailable authority into an invalid-token error. */
    static IntrospectionResult check(TokenIntrospector introspector, String token) {
        try {
            return introspector.introspect(token);
        }
        catch (IntrospectionException ex) {
            throw new BadJwtException("The token could not be verified because token introspection is unavailable",
                    ex);
        }
    }

    static Jwt toJwt(String token, Map<String, Object> claims) {
        if (claims.isEmpty()) {
            throw new BadJwtException("The introspection response has no claims");
        }
        Map<String, Object> converted = new LinkedHashMap<>(claims);
        for (String time : new String[] { "exp", "iat", "nbf" }) {
            if (converted.containsKey(time)) {
                Instant instant = CachingTokenIntrospector.instant(converted.get(time));
                if (instant == null) {
                    converted.remove(time);
                }
                else {
                    converted.put(time, instant);
                }
            }
        }
        try {
            return Jwt.withTokenValue(token)
                    .header("alg", "none")
                    .header("typ", "introspected")
                    .claims(target -> target.putAll(converted))
                    .build();
        }
        catch (IllegalArgumentException ex) {
            throw new BadJwtException("The introspection response has inconsistent claims: " + ex.getMessage(), ex);
        }
    }
}
