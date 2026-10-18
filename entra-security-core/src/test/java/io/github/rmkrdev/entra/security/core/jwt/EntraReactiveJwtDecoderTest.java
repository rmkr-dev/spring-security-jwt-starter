package io.github.rmkrdev.entra.security.core.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.rmkrdev.entra.security.core.test.TestTokens;
import reactor.test.StepVerifier;

/**
 * The reactive decoder accepts and rejects exactly what the servlet decoder does.
 */
class EntraReactiveJwtDecoderTest {

    private static final TestTokens TOKENS = new TestTokens("https://login.microsoftonline.com");

    private final ImmutableJWKSet<SecurityContext> keys = keys();
    private final List<String> issuers = List.of(TOKENS.v2Issuer(), TestTokens.V1_ISSUER);
    private final List<String> audiences = List.of("api://" + TestTokens.CLIENT_ID, TestTokens.CLIENT_ID);
    private final JwtDecoder servlet = EntraJwtDecoders.create(keys, issuers, audiences, TestTokens.TENANT_ID,
            Duration.ofSeconds(60));
    private final EntraReactiveJwtDecoder reactive = EntraReactiveJwtDecoder.create(keys, issuers, audiences,
            TestTokens.TENANT_ID, Duration.ofSeconds(60));

    @Test
    void acceptsAValidToken() {
        String token = TOKENS.user().groups("g-1").build();
        StepVerifier.create(reactive.decode(token))
                .assertNext(jwt -> {
                    assertThat(jwt.getClaims()).isEqualTo(servlet.decode(token).getClaims());
                    assertThat(jwt.getClaimAsString("tid")).isEqualTo(TestTokens.TENANT_ID);
                })
                .verifyComplete();
    }

    @Test
    void rejectsWhatTheServletDecoderRejects() {
        List<String> invalid = List.of(
                TOKENS.user().audience("api://someone-else").build(),
                TOKENS.user().issuer("https://evil.example/").build(),
                TOKENS.user().claim("tid", "99999999-9999-9999-9999-999999999999").build(),
                TOKENS.user().expiresAt(Instant.now().minusSeconds(600)).build(),
                TOKENS.user().signedWithUnknownKey().build(),
                TOKENS.user().hmac().build(),
                "not-a-jwt");
        for (String token : invalid) {
            Throwable servletError = catchError(() -> servlet.decode(token));
            StepVerifier.create(reactive.decode(token))
                    .expectErrorSatisfies(error -> {
                        assertThat(error).isInstanceOf(JwtException.class).hasSameClassAs(servletError);
                        assertThat(error.getMessage()).isEqualTo(servletError.getMessage());
                        assertThat(JwtAuthenticationOutcomes.reason(error))
                                .isEqualTo(JwtAuthenticationOutcomes.reason(servletError));
                    })
                    .verify();
        }
    }

    @Test
    void validationErrorsKeepTheirType() {
        StepVerifier.create(reactive.decode(TOKENS.user().audience("other").build()))
                .expectError(JwtValidationException.class)
                .verify();
        StepVerifier.create(reactive.decode("not-a-jwt"))
                .expectError(BadJwtException.class)
                .verify();
    }

    @Test
    void errorsAreSignalledNotThrown() {
        assertThatCode(() -> reactive.decode("not-a-jwt")).doesNotThrowAnyException();
        assertThatThrownBy(() -> reactive.decode("not-a-jwt").block()).isInstanceOf(BadJwtException.class);
    }

    private static Throwable catchError(Runnable call) {
        try {
            call.run();
        }
        catch (RuntimeException ex) {
            return ex;
        }
        throw new AssertionError("servlet decoder accepted the token");
    }

    private static ImmutableJWKSet<SecurityContext> keys() {
        try {
            return new ImmutableJWKSet<>(JWKSet.parse(TOKENS.jwksJson()));
        }
        catch (java.text.ParseException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
