package io.github.rmkrdev.entra.security.core.test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Mints Entra-shaped access tokens signed with a locally generated RSA key, and exposes the matching
 * JWKS. Never talks to a real Entra tenant.
 */
public final class TestTokens {

    public static final String TENANT_ID = "11111111-1111-1111-1111-111111111111";
    public static final String CLIENT_ID = "22222222-2222-2222-2222-222222222222";
    public static final String USER_OID = "33333333-3333-3333-3333-333333333333";
    public static final String PEER_APP_ID = "44444444-4444-4444-4444-444444444444";
    public static final String SPA_APP_ID = "55555555-5555-5555-5555-555555555555";
    public static final String V1_ISSUER = "https://sts.windows.net/" + TENANT_ID + "/";

    private final RSAKey signingKey;
    private final RSAKey otherKey;
    private final String v2Issuer;

    public TestTokens(String authorityHost) {
        this.signingKey = generate("test-kid");
        this.otherKey = generate("test-kid");
        String host = authorityHost.endsWith("/") ? authorityHost.substring(0, authorityHost.length() - 1)
                : authorityHost;
        this.v2Issuer = host + "/" + TENANT_ID + "/v2.0";
    }

    /** The JWKS document holding the public signing key. */
    public String jwksJson() {
        return new JWKSet(signingKey.toPublicJWK()).toString();
    }

    public String v2Issuer() {
        return v2Issuer;
    }

    /** A v2 delegated user token with {@code scp}. */
    public Builder user() {
        return new Builder()
                .claim("iss", v2Issuer)
                .claim("aud", CLIENT_ID)
                .claim("tid", TENANT_ID)
                .claim("oid", USER_OID)
                .claim("sub", "user-subject")
                .claim("azp", SPA_APP_ID)
                .claim("scp", "access_as_user")
                .claim("ver", "2.0")
                .claim("name", "Test User")
                .claim("preferred_username", "test.user@contoso.example");
    }

    /** A v2 app-only token ({@code idtyp=app}, no {@code scp}). */
    public Builder service() {
        String spOid = UUID.randomUUID().toString();
        return new Builder()
                .claim("iss", v2Issuer)
                .claim("aud", CLIENT_ID)
                .claim("tid", TENANT_ID)
                .claim("oid", spOid)
                .claim("sub", spOid)
                .claim("azp", PEER_APP_ID)
                .claim("idtyp", "app")
                .claim("ver", "2.0");
    }

    private static RSAKey generate(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        }
        catch (JOSEException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * Fluent token builder.
     */
    public final class Builder {

        private final Map<String, Object> claims = new LinkedHashMap<>();
        private Instant issuedAt = Instant.now();
        private Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
        private boolean hmac;
        private boolean foreignKey;

        private Builder() {
        }

        public Builder claim(String name, Object value) {
            claims.put(name, value);
            return this;
        }

        public Builder without(String name) {
            claims.remove(name);
            return this;
        }

        public Builder groups(String... groups) {
            return claim("groups", List.of(groups));
        }

        public Builder roles(String... roles) {
            return claim("roles", List.of(roles));
        }

        public Builder audience(String audience) {
            return claim("aud", audience);
        }

        public Builder issuer(String issuer) {
            return claim("iss", issuer);
        }

        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public Builder issuedAt(Instant issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        /** Signs with HS256 instead of RS256. */
        public Builder hmac() {
            this.hmac = true;
            return this;
        }

        /** Signs with an RSA key that is not in the JWKS (same kid). */
        public Builder signedWithUnknownKey() {
            this.foreignKey = true;
            return this;
        }

        public String build() {
            JWTClaimsSet.Builder set = new JWTClaimsSet.Builder()
                    .issueTime(Date.from(issuedAt))
                    .notBeforeTime(Date.from(issuedAt))
                    .expirationTime(Date.from(expiresAt))
                    .jwtID(UUID.randomUUID().toString());
            claims.forEach(set::claim);
            try {
                JWSSigner signer;
                JWSHeader header;
                if (hmac) {
                    signer = new MACSigner("0123456789abcdef0123456789abcdef0123456789abcdef".getBytes());
                    header = new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT)
                            .keyID(signingKey.getKeyID()).build();
                }
                else {
                    RSAKey key = foreignKey ? otherKey : signingKey;
                    signer = new RSASSASigner(key);
                    header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT)
                            .keyID(key.getKeyID()).build();
                }
                SignedJWT jwt = new SignedJWT(header, set.build());
                jwt.sign(signer);
                return jwt.serialize();
            }
            catch (JOSEException ex) {
                throw new IllegalStateException(ex);
            }
        }
    }
}
