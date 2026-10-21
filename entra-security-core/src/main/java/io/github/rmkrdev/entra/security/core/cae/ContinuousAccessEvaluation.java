package io.github.rmkrdev.entra.security.core.cae;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.security.oauth2.jwt.Jwt;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The small part of Continuous Access Evaluation this library supports: declaring the {@code cp1} client
 * capability, reading an {@code insufficient_claims} challenge from a {@code WWW-Authenticate} header, and
 * building one.
 */
public final class ContinuousAccessEvaluation {

    /** The client capability that tells Entra this client can handle claims challenges. */
    public static final String CP1 = "cp1";

    /** The {@code claims} request parameter that declares {@link #CP1}. */
    public static final String CP1_CLAIMS = "{\"access_token\":{\"xms_cc\":{\"values\":[\"cp1\"]}}}";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern ERROR = Pattern.compile("error\\s*=\\s*\"?insufficient_claims\"?",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern CLAIMS = Pattern.compile("claims\\s*=\\s*\"([^\"]*)\"", Pattern.CASE_INSENSITIVE);

    private ContinuousAccessEvaluation() {
    }

    /**
     * The {@code claims} parameter for a token request: {@link #CP1_CLAIMS} when {@code declareCp1}, merged with the
     * challenge claims when there are any. {@code null} when neither applies.
     */
    public static String requestClaims(boolean declareCp1, String challengeClaims) {
        if (challengeClaims == null || challengeClaims.isBlank()) {
            return declareCp1 ? CP1_CLAIMS : null;
        }
        if (!declareCp1) {
            return challengeClaims;
        }
        try {
            JsonNode parsed = JSON.readTree(challengeClaims);
            ObjectNode root = parsed instanceof ObjectNode object ? object : JSON.createObjectNode();
            ObjectNode accessToken = root.get("access_token") instanceof ObjectNode node ? node
                    : root.putObject("access_token");
            ObjectNode xmsCc = accessToken.get("xms_cc") instanceof ObjectNode node ? node
                    : accessToken.putObject("xms_cc");
            ArrayNode values = xmsCc.get("values") instanceof ArrayNode node ? node : xmsCc.putArray("values");
            boolean present = false;
            for (JsonNode value : values) {
                present |= CP1.equals(value.asString());
            }
            if (!present) {
                values.add(CP1);
            }
            return JSON.writeValueAsString(root);
        }
        catch (Exception ex) {
            return challengeClaims;
        }
    }

    /**
     * The decoded claims of an {@code insufficient_claims} challenge in a {@code WWW-Authenticate} header value.
     */
    public static Optional<String> claimsChallenge(String wwwAuthenticate) {
        if (wwwAuthenticate == null || !ERROR.matcher(wwwAuthenticate).find()) {
            return Optional.empty();
        }
        Matcher claims = CLAIMS.matcher(wwwAuthenticate);
        if (!claims.find() || claims.group(1).isBlank()) {
            return Optional.empty();
        }
        String encoded = claims.group(1).trim();
        try {
            return Optional.of(new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8));
        }
        catch (IllegalArgumentException notStandard) {
            try {
                return Optional.of(new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8));
            }
            catch (IllegalArgumentException notUrl) {
                return encoded.startsWith("{") ? Optional.of(encoded) : Optional.empty();
            }
        }
    }

    /** Whether the token says its client handles claims challenges ({@code xms_cc} contains {@code cp1}). */
    public static boolean supportsClaimsChallenge(Jwt jwt) {
        if (jwt == null) {
            return false;
        }
        Object xmsCc = jwt.getClaims().get("xms_cc");
        if (xmsCc instanceof Collection<?> values) {
            return values.stream().anyMatch(value -> CP1.equalsIgnoreCase(String.valueOf(value)));
        }
        return xmsCc != null && CP1.equalsIgnoreCase(xmsCc.toString());
    }

    /** {@code Bearer error="insufficient_claims", error_description="…", claims="<base64>"}. */
    public static String challengeHeader(String claims, String description) {
        String encoded = Base64.getEncoder().encodeToString(claims.getBytes(StandardCharsets.UTF_8));
        String safe = description == null ? "Additional claims are required" : description.replace("\"", "'");
        return "Bearer error=\"insufficient_claims\", error_description=\"" + safe + "\", claims=\"" + encoded + "\"";
    }
}
