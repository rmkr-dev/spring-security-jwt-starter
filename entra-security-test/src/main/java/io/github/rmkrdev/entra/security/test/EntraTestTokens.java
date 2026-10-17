package io.github.rmkrdev.entra.security.test;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Mints Entra-shaped access tokens for one API (tenant and client id), signed by an {@link EntraMockAuthority}.
 * <p>
 * Tokens look like the ones Entra issues: v2 by default ({@code iss={authority}/{tid}/v2.0}, {@code azp},
 * {@code ver=2.0}) or v1 with {@link TokenBuilder#v1()} ({@code iss=https://sts.windows.net/{tid}/},
 * {@code appid}, {@code ver=1.0}).
 *
 * <pre>{@code
 * String user = tokens.user().groups(READERS_GROUP).bearer();
 * String peer = tokens.service().appRoles("Orders.Sync").bearer();
 * mvc.perform(get("/api/orders").header("Authorization", user)).andExpect(status().isOk());
 * }</pre>
 */
public final class EntraTestTokens {

    /** Default {@code oid} of user tokens. */
    public static final String USER_OBJECT_ID = "a0a0a0a0-0000-4000-8000-000000000001";
    /** Default client (for example a SPA) that requested user tokens ({@code azp}/{@code appid}). */
    public static final String USER_CLIENT_APP_ID = "c0c0c0c0-0000-4000-8000-000000000001";
    /** Default {@code oid} of service tokens (the calling service principal). */
    public static final String SERVICE_OBJECT_ID = "a0a0a0a0-0000-4000-8000-000000000002";
    /** Default calling application of service tokens ({@code azp}/{@code appid}). */
    public static final String SERVICE_APP_ID = "c0c0c0c0-0000-4000-8000-000000000002";

    private final EntraMockAuthority authority;
    private final String tenantId;
    private final String clientId;

    EntraTestTokens(EntraMockAuthority authority, String tenantId, String clientId) {
        this.authority = Objects.requireNonNull(authority, "authority");
        this.tenantId = requireText(tenantId, "tenantId");
        this.clientId = requireText(clientId, "clientId");
    }

    public String tenantId() {
        return tenantId;
    }

    public String clientId() {
        return clientId;
    }

    public EntraMockAuthority authority() {
        return authority;
    }

    /**
     * A delegated user token: {@code scp=access_as_user}, no {@code idtyp}, the default user {@code oid} and a
     * display name and username.
     */
    public TokenBuilder user() {
        return new TokenBuilder(false)
                .objectId(USER_OBJECT_ID)
                .claim("sub", "user-" + USER_OBJECT_ID)
                .appId(USER_CLIENT_APP_ID)
                .scopes("access_as_user")
                .name("Test User")
                .username("test.user@contoso.example");
    }

    /**
     * An app-only (client-credentials) token: {@code idtyp=app}, no {@code scp}, the default service
     * {@code oid} and calling application.
     */
    public TokenBuilder service() {
        return new TokenBuilder(true)
                .objectId(SERVICE_OBJECT_ID)
                .claim("sub", SERVICE_OBJECT_ID)
                .appId(SERVICE_APP_ID)
                .claim("idtyp", "app");
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be empty");
        }
        return value;
    }

    /**
     * Fluent builder for one token. Every setter returns the builder; finish with {@link #build()} or
     * {@link #bearer()}.
     */
    public final class TokenBuilder {

        private final Map<String, Object> claims = new LinkedHashMap<>();
        private final boolean service;
        private boolean v1;
        private String appId;
        private String audience;
        private String issuer;
        private Instant issuedAt = Instant.now();
        private Instant notBefore;
        private Instant expiresAt;
        private boolean unknownKey;
        private boolean hmac;

        private TokenBuilder(boolean service) {
            this.service = service;
        }

        /** Sets any claim; {@code null} removes it. */
        public TokenBuilder claim(String name, Object value) {
            if (value == null) {
                claims.remove(name);
            }
            else {
                claims.put(name, value);
            }
            return this;
        }

        /** Removes a claim. */
        public TokenBuilder without(String name) {
            claims.remove(name);
            if ("azp".equals(name) || "appid".equals(name)) {
                appId = null;
            }
            if ("aud".equals(name)) {
                audience = "";
            }
            if ("iss".equals(name)) {
                issuer = "";
            }
            return this;
        }

        /** The {@code oid} claim. */
        public TokenBuilder objectId(String objectId) {
            return claim("oid", objectId);
        }

        /** The calling application: {@code azp} in v2 tokens, {@code appid} in v1 tokens. */
        public TokenBuilder appId(String appId) {
            this.appId = appId;
            return this;
        }

        /** The {@code groups} claim (object ids or names). */
        public TokenBuilder groups(String... groups) {
            claims.remove("_claim_names");
            claims.remove("_claim_sources");
            claims.remove("hasgroups");
            return claim("groups", List.of(groups));
        }

        /**
         * Marks the token as a group overage: no {@code groups} claim, and {@code _claim_names}/
         * {@code _claim_sources} pointing at Graph, the way Entra does for users in too many groups. Register the
         * user's groups with {@link EntraMockAuthority#registerGroups(String, String...)}.
         */
        public TokenBuilder groupOverage() {
            claims.remove("groups");
            claim("_claim_names", Map.of("groups", "src1"));
            return claim("_claim_sources", Map.of("src1",
                    Map.of("endpoint", "https://graph.microsoft.com/v1.0/users/" + claims.get("oid") + "/getMemberObjects")));
        }

        /** The {@code roles} claim: app roles assigned to the user or the calling application. */
        public TokenBuilder appRoles(String... appRoles) {
            return claim("roles", List.of(appRoles));
        }

        /** The {@code scp} claim (space separated in the token). */
        public TokenBuilder scopes(String... scopes) {
            return claim("scp", scopes.length == 0 ? null : String.join(" ", Arrays.asList(scopes)));
        }

        /** The {@code name} claim. */
        public TokenBuilder name(String name) {
            return claim("name", name);
        }

        /** The {@code preferred_username} claim (or {@code upn} for v1 tokens). */
        public TokenBuilder username(String username) {
            return claim("preferred_username", username);
        }

        /** Overrides the audience (default: the API's client id). */
        public TokenBuilder audience(String audience) {
            this.audience = audience;
            return this;
        }

        /** Overrides the issuer. */
        public TokenBuilder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /** Overrides the {@code tid} claim. */
        public TokenBuilder tenantId(String tenantId) {
            return claim("tid", tenantId);
        }

        /** Issues a v1 token: {@code sts.windows.net} issuer, {@code appid}, {@code api://} audience, {@code ver=1.0}. */
        public TokenBuilder v1() {
            this.v1 = true;
            return this;
        }

        /** Lifetime from now (default one hour). A negative value yields an expired token. */
        public TokenBuilder expiresIn(Duration lifetime) {
            this.expiresAt = Instant.now().plus(lifetime);
            return this;
        }

        public TokenBuilder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        /** An already expired token. */
        public TokenBuilder expired() {
            this.issuedAt = Instant.now().minus(Duration.ofHours(2));
            this.expiresAt = Instant.now().minus(Duration.ofHours(1));
            return this;
        }

        public TokenBuilder issuedAt(Instant issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        public TokenBuilder notBefore(Instant notBefore) {
            this.notBefore = notBefore;
            return this;
        }

        /** Signs with an RSA key that is not in the authority's JWKS (same {@code kid}): must be rejected. */
        public TokenBuilder signedWithUnknownKey() {
            this.unknownKey = true;
            return this;
        }

        /** Signs with HS256 instead of RS256: must be rejected. */
        public TokenBuilder signedWithHmac() {
            this.hmac = true;
            return this;
        }

        /** The compact serialized JWT. */
        public String build() {
            JWTClaimsSet.Builder set = new JWTClaimsSet.Builder()
                    .issueTime(Date.from(issuedAt))
                    .notBeforeTime(Date.from(notBefore != null ? notBefore : issuedAt))
                    .expirationTime(Date.from(expiresAt != null ? expiresAt : issuedAt.plus(Duration.ofHours(1))))
                    .jwtID(UUID.randomUUID().toString());
            set.claim("iss", issuer != null ? emptyToNull(issuer)
                    : v1 ? "https://sts.windows.net/" + tenantId + "/" : authority.issuer(tenantId));
            set.claim("aud", audience != null ? emptyToNull(audience) : v1 ? "api://" + clientId : clientId);
            set.claim("tid", tenantId);
            set.claim("ver", v1 ? "1.0" : "2.0");
            if (appId != null) {
                set.claim(v1 ? "appid" : "azp", appId);
                set.claim(v1 ? "appidacr" : "azpacr", service ? "1" : "0");
            }
            claims.forEach((name, value) -> {
                if (v1 && "preferred_username".equals(name)) {
                    set.claim("upn", value);
                }
                else {
                    set.claim(name, value);
                }
            });
            return sign(set.build());
        }

        /** {@code "Bearer " + build()}, ready for an {@code Authorization} header. */
        public String bearer() {
            return "Bearer " + build();
        }

        private String sign(JWTClaimsSet claimsSet) {
            RSAKey key = unknownKey ? authority.foreignKey() : authority.signingKey();
            try {
                JWSSigner signer;
                JWSHeader header;
                if (hmac) {
                    byte[] secret = new byte[32];
                    new java.security.SecureRandom().nextBytes(secret);
                    signer = new MACSigner(secret);
                    header = new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).keyID(key.getKeyID())
                            .build();
                }
                else {
                    signer = new RSASSASigner(key);
                    header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(key.getKeyID())
                            .build();
                }
                SignedJWT jwt = new SignedJWT(header, claimsSet);
                jwt.sign(signer);
                return jwt.serialize();
            }
            catch (JOSEException ex) {
                throw new IllegalStateException("Could not sign the test token", ex);
            }
        }

        private String emptyToNull(String value) {
            return value.isEmpty() ? null : value;
        }
    }
}
