package io.github.rmkrdev.entra.security.core.jwt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Helpers for reading Entra-specific claims, tolerant of v1 and v2 token shapes.
 */
public final class EntraClaims {

    private EntraClaims() {
    }

    /**
     * The calling client application: {@code azp} (v2) or {@code appid} (v1).
     */
    public static String appId(Jwt jwt) {
        String azp = jwt.getClaimAsString(EntraClaimNames.AUTHORIZED_PARTY);
        return azp != null ? azp : jwt.getClaimAsString(EntraClaimNames.APP_ID);
    }

    /**
     * The delegated scopes from {@code scp}, which Entra emits as a space-separated string.
     */
    public static List<String> scopes(Jwt jwt) {
        Object value = jwt.getClaims().get(EntraClaimNames.SCOPE);
        if (value instanceof String text) {
            if (text.isBlank()) {
                return Collections.emptyList();
            }
            return Arrays.stream(text.trim().split("\\s+")).toList();
        }
        return stringList(jwt, EntraClaimNames.SCOPE);
    }

    /**
     * A claim that may be a JSON array or a single string, as a list of strings.
     */
    public static List<String> stringList(Jwt jwt, String claim) {
        Object value = jwt.getClaims().get(claim);
        if (value == null) {
            return Collections.emptyList();
        }
        if (value instanceof Collection<?> collection) {
            List<String> result = new ArrayList<>(collection.size());
            for (Object item : collection) {
                if (item != null) {
                    result.add(item.toString());
                }
            }
            return result;
        }
        return List.of(value.toString());
    }

    /**
     * Whether Entra omitted the {@code groups} claim because the user is in too many groups.
     * <p>
     * JWTs signal this with {@code _claim_names: {"groups": "src1"}}; implicit-flow tokens use
     * {@code hasgroups: true}.
     */
    public static boolean isGroupOverage(Jwt jwt) {
        Object hasGroups = jwt.getClaims().get(EntraClaimNames.HAS_GROUPS);
        if (Boolean.TRUE.equals(hasGroups) || "true".equalsIgnoreCase(String.valueOf(hasGroups))) {
            return true;
        }
        Object claimNames = jwt.getClaims().get(EntraClaimNames.CLAIM_NAMES);
        return claimNames instanceof Map<?, ?> names && names.containsKey(EntraClaimNames.GROUPS);
    }

    /**
     * The best available username: {@code preferred_username}, {@code upn} or {@code unique_name}.
     */
    public static String username(Jwt jwt) {
        for (String claim : List.of(EntraClaimNames.PREFERRED_USERNAME, EntraClaimNames.UPN,
                EntraClaimNames.UNIQUE_NAME)) {
            String value = jwt.getClaimAsString(claim);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
