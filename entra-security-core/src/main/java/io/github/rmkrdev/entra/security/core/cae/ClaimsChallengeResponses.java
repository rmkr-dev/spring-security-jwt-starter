package io.github.rmkrdev.entra.security.core.cae;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import io.github.rmkrdev.entra.security.core.web.ProblemDetails;

/**
 * The response for a {@link ClaimsChallengeException}: {@code 401} with an {@code insufficient_claims} challenge
 * when the caller's token carries {@code xms_cc=cp1}, otherwise a plain {@code 403}.
 */
public final class ClaimsChallengeResponses {

    private ClaimsChallengeResponses() {
    }

    public static ResponseEntity<Map<String, Object>> response(ClaimsChallengeException ex,
            Authentication authentication, String instance) {
        Jwt jwt = authentication instanceof AbstractOAuth2TokenAuthenticationToken<?> token
                && token.getToken() instanceof Jwt value ? value : null;
        if (ContinuousAccessEvaluation.supportsClaimsChallenge(jwt)) {
            Map<String, Object> body = ProblemDetails.body(HttpStatus.UNAUTHORIZED, ex.getMessage(),
                    "insufficient_claims", instance);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE,
                            ContinuousAccessEvaluation.challengeHeader(ex.getClaims(), ex.getMessage()))
                    .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                    .body(body);
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(ProblemDetails.body(HttpStatus.FORBIDDEN, ex.getMessage(), "insufficient_claims", instance));
    }
}
