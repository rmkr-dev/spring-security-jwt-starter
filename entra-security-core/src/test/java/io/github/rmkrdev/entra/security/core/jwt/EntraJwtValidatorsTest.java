package io.github.rmkrdev.entra.security.core.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

class EntraJwtValidatorsTest {

    private static final String TID = "11111111-1111-1111-1111-111111111111";

    private final OAuth2TokenValidator<Jwt> validator = EntraJwtDecoders.validator(
            List.of("https://sts.windows.net/" + TID + "/", "https://login.microsoftonline.com/" + TID + "/v2.0"),
            List.of("api://client", "client"), TID, Duration.ofSeconds(30));

    @Test
    void acceptsV1AndV2() {
        assertThat(validator.validate(jwt("https://sts.windows.net/" + TID + "/", "api://client", TID, 60))
                .hasErrors()).isFalse();
        assertThat(validator.validate(jwt("https://login.microsoftonline.com/" + TID + "/v2.0", "client", TID, 60))
                .hasErrors()).isFalse();
    }

    @Test
    void rejectsWrongIssuerAudienceTenantAndExpiry() {
        assertThat(validator.validate(jwt("https://evil.example/", "client", TID, 60)).getErrors())
                .anyMatch(e -> e.getDescription().contains("iss"));
        assertThat(validator.validate(jwt("https://sts.windows.net/" + TID + "/", "other", TID, 60)).getErrors())
                .anyMatch(e -> e.getDescription().contains("aud"));
        assertThat(validator.validate(jwt("https://sts.windows.net/" + TID + "/", "client",
                "99999999-9999-9999-9999-999999999999", 60)).getErrors())
                .anyMatch(e -> e.getDescription().contains("tid"));
        assertThat(validator.validate(jwt("https://sts.windows.net/" + TID + "/", "client", TID, -120))
                .hasErrors()).isTrue();
    }

    @Test
    void rejectIdTokensFlagRequiresAnAccessTokenClaim() {
        OAuth2TokenValidator<Jwt> strict = EntraJwtDecoders.validator(
                List.of("https://login.microsoftonline.com/" + TID + "/v2.0"), List.of("client"), TID, List.of(),
                true, Duration.ofSeconds(30));
        Jwt idToken = jwt("https://login.microsoftonline.com/" + TID + "/v2.0", "client", TID, 60);
        assertThat(strict.validate(idToken).getErrors())
                .anyMatch(error -> error.getDescription().contains("not an Entra access token"));
        Jwt base = jwt("https://login.microsoftonline.com/" + TID + "/v2.0", "client", TID, 60);
        Jwt accessToken = Jwt.withTokenValue(base.getTokenValue()).headers(h -> h.putAll(base.getHeaders()))
                .claims(c -> {
                    c.putAll(base.getClaims());
                    c.put("scp", "access_as_user");
                }).issuedAt(base.getIssuedAt()).expiresAt(base.getExpiresAt()).build();
        assertThat(strict.validate(accessToken).hasErrors()).isFalse();
        assertThat(validator.validate(idToken).hasErrors()).isFalse();
    }

    @Test
    void tenantAllowListReplacesTheSingleTenantCheck() {
        String other = "22222222-2222-2222-2222-222222222222";
        OAuth2TokenValidator<Jwt> allowList = EntraJwtDecoders.validator(
                List.of("https://login.microsoftonline.com/" + TID + "/v2.0",
                        "https://login.microsoftonline.com/" + other + "/v2.0"),
                List.of("client"), null, List.of(TID, other), false, Duration.ofSeconds(30));
        assertThat(allowList.validate(jwt("https://login.microsoftonline.com/" + other + "/v2.0", "client", other, 60))
                .hasErrors()).isFalse();
        assertThat(allowList.validate(jwt("https://login.microsoftonline.com/" + TID + "/v2.0", "client",
                "99999999-9999-9999-9999-999999999999", 60)).getErrors())
                .anyMatch(error -> error.getDescription().contains("tid"));
    }

    @Test
    void clockSkewTolerated() {
        assertThat(validator.validate(jwt("https://sts.windows.net/" + TID + "/", "client", TID, -10))
                .hasErrors()).isFalse();
    }

    private static Jwt jwt(String iss, String aud, String tid, long expiresInSeconds) {
        Instant exp = Instant.now().plusSeconds(expiresInSeconds);
        return Jwt.withTokenValue("t").header("alg", "RS256")
                .claims(c -> c.putAll(Map.of("iss", iss, "aud", List.of(aud), "tid", tid)))
                .issuedAt(exp.minusSeconds(3600)).expiresAt(exp).build();
    }
}
