package io.github.rmkrdev.entra.security.core.web;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import io.github.rmkrdev.entra.security.core.token.EntraInteractionRequiredException;

/**
 * The {@code 403} response for an {@link EntraInteractionRequiredException}, shared by the servlet and the
 * reactive exception handlers.
 * <p>
 * Body: problem details with {@code error} set to {@code consent_required} or {@code interaction_required},
 * the downstream {@code scope}, and the {@code claims} challenge when Entra sent one. Header:
 * {@code WWW-Authenticate: Bearer error="...", error_description="...", claims="<base64 claims>"}, the shape
 * Microsoft's client libraries read to start a step-up sign-in.
 */
public final class InteractionRequiredProblems {

    private InteractionRequiredProblems() {
    }

    public static ResponseEntity<Map<String, Object>> response(EntraInteractionRequiredException ex,
            String instance) {
        String code = ex.getProblemErrorCode();
        String detail = ex.isConsentRequired()
                ? "A downstream API needs consent that the user has not granted; sign in again interactively "
                        + "and consent"
                : "A downstream API requires the user to sign in again interactively (for example for MFA or "
                        + "Conditional Access)";
        Map<String, Object> body = ProblemDetails.body(HttpStatus.FORBIDDEN, detail, code, instance);
        if (ex.getScope() != null) {
            body.put("scope", ex.getScope());
        }
        if (ex.getClaims() != null) {
            body.put("claims", ex.getClaims());
        }
        StringBuilder challenge = new StringBuilder("Bearer error=\"").append(code)
                .append("\", error_description=\"").append(detail).append('"');
        if (ex.getClaims() != null) {
            challenge.append(", claims=\"")
                    .append(Base64.getEncoder().encodeToString(ex.getClaims().getBytes(StandardCharsets.UTF_8)))
                    .append('"');
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .header(HttpHeaders.WWW_AUTHENTICATE, challenge.toString())
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(body);
    }
}
