package io.github.rmkrdev.entra.security.core.introspect;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Turns the claims an authority returned into the claims the rest of the starter reads ({@code oid}, {@code tid},
 * {@code azp}, {@code scp}, {@code roles}, ...). Every returned claim is kept; a mapping {@code target -> source}
 * additionally copies {@code source} to {@code target} when the response has {@code source} and does not already
 * have {@code target}.
 */
public final class IntrospectedClaimsMapper {

    private final Map<String, String> mapping;
    private final Map<String, Object> defaults;

    /**
     * @param mapping  target claim to source field
     * @param defaults claims added when absent after mapping
     */
    public IntrospectedClaimsMapper(Map<String, String> mapping, Map<String, Object> defaults) {
        this.mapping = Map.copyOf(mapping == null ? Map.of() : mapping);
        this.defaults = Map.copyOf(defaults == null ? Map.of() : defaults);
    }

    /**
     * RFC 7662 responses: {@code scope} becomes {@code scp} and {@code client_id} becomes {@code azp}, plus the
     * given mapping (which wins on conflicts).
     */
    public static IntrospectedClaimsMapper rfc7662(Map<String, String> custom) {
        Map<String, String> mapping = new LinkedHashMap<>();
        mapping.put("scp", "scope");
        mapping.put("azp", "client_id");
        if (custom != null) {
            mapping.putAll(custom);
        }
        return new IntrospectedClaimsMapper(mapping, Map.of());
    }

    /**
     * Userinfo and Graph {@code /me} responses: {@code id} becomes {@code oid}, {@code userPrincipalName} becomes
     * {@code preferred_username} and {@code displayName} becomes {@code name}; the token is always a user token
     * ({@code idtyp=user}).
     */
    public static IntrospectedClaimsMapper userInfo(Map<String, String> custom) {
        Map<String, String> mapping = new LinkedHashMap<>();
        mapping.put("oid", "id");
        mapping.put("preferred_username", "userPrincipalName");
        mapping.put("name", "displayName");
        if (custom != null) {
            mapping.putAll(custom);
        }
        return new IntrospectedClaimsMapper(mapping, Map.of("idtyp", "user"));
    }

    public Map<String, Object> map(Map<String, Object> claims) {
        Map<String, Object> result = new LinkedHashMap<>(claims);
        mapping.forEach((target, source) -> {
            Object value = claims.get(source);
            if (value != null && !claims.containsKey(target)) {
                result.put(target, value);
            }
        });
        defaults.forEach(result::putIfAbsent);
        return result;
    }
}
