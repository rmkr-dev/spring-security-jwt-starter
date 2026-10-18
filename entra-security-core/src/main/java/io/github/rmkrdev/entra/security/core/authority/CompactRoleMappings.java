package io.github.rmkrdev.entra.security.core.authority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Parses the single-line role mapping syntax used where nested maps are awkward, such as environment
 * variables and Kubernetes ConfigMap scalars.
 * <p>
 * The syntax is a list of {@code key=ROLE} entries:
 * <ul>
 *   <li>Entries are separated by {@code ;} or {@code ,}. Blank entries, such as a trailing separator,
 *       are ignored.</li>
 *   <li>One entry can map a key to several roles separated by {@code |}: {@code key=ADMIN|READER}.
 *       Repeating a key adds to its roles, so {@code key=ADMIN,key=READER} is the same.</li>
 *   <li>Whitespace around keys, roles and separators is ignored.</li>
 * </ul>
 * For example {@code 0b5c1d7e-...=ORDERS_ADMIN|ORDERS_READ;7f3a...=ORDERS_READ}.
 * <p>
 * Roles may be given with or without the {@code ROLE_} prefix, as in the map form. Keys that contain
 * {@code =}, {@code ;}, {@code ,} or {@code |} cannot be written in this syntax; use the map form for them.
 */
public final class CompactRoleMappings {

    private static final Pattern GUID = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern ENTRY_SEPARATOR = Pattern.compile("[;,]");
    private static final Pattern ROLE_SEPARATOR = Pattern.compile("\\|");
    private static final Pattern WHITESPACE = Pattern.compile("\\s");

    /** What the keys of a mapping are, which decides how they are validated. */
    public enum KeyType {

        /** Group object ids, or group names when the groups claim emits names. Any text is accepted. */
        GROUP("group"),

        /** App role values from the roles claim. Entra does not allow whitespace in them. */
        APP_ROLE("app role"),

        /** Calling application (client) ids from azp/appid. Must be GUIDs. */
        CLIENT_ID("client id");

        private final String label;

        KeyType(String label) {
            this.label = label;
        }

        String label() {
            return label;
        }
    }

    private CompactRoleMappings() {
    }

    /**
     * Parses a compact mapping string.
     *
     * @param property the property name, used in error messages
     * @param value    the compact value; {@code null} or blank gives an empty map
     * @param keyType  how keys are validated
     * @return the mappings in the order the keys first appear
     * @throws IllegalArgumentException if the value is malformed; the message names the property, the
     *                                  entry and what is wrong with it
     */
    public static Map<String, List<String>> parse(String property, String value, KeyType keyType) {
        Map<String, Set<String>> result = new LinkedHashMap<>();
        if (value == null || value.isBlank()) {
            return Collections.emptyMap();
        }
        String[] entries = ENTRY_SEPARATOR.split(value, -1);
        for (int i = 0; i < entries.length; i++) {
            String entry = entries[i].trim();
            if (entry.isEmpty()) {
                continue;
            }
            int position = i + 1;
            int equals = entry.indexOf('=');
            if (equals < 0) {
                throw error(property, position, entry, "is missing '='; expected <" + keyType.label()
                        + ">=<ROLE>[|<ROLE>...]");
            }
            String key = entry.substring(0, equals).trim();
            String roles = entry.substring(equals + 1).trim();
            if (key.isEmpty()) {
                throw error(property, position, entry, "has no " + keyType.label() + " before '='");
            }
            validateKey(property, position, entry, key, keyType);
            if (roles.isEmpty()) {
                throw error(property, position, entry, "has no role after '='");
            }
            if (roles.indexOf('=') >= 0) {
                throw error(property, position, entry, "contains more than one '='; separate entries with ';' "
                        + "or ','");
            }
            Set<String> target = result.computeIfAbsent(key, k -> new LinkedHashSet<>());
            for (String raw : ROLE_SEPARATOR.split(roles, -1)) {
                String role = raw.trim();
                if (role.isEmpty()) {
                    throw error(property, position, entry, "has an empty role; separate roles with a single '|'");
                }
                if (WHITESPACE.matcher(role).find()) {
                    throw error(property, position, entry, "has role '" + role + "' with whitespace in it; "
                            + "separate roles with '|'");
                }
                target.add(role);
            }
        }
        Map<String, List<String>> mappings = new LinkedHashMap<>();
        result.forEach((key, roles) -> mappings.put(key, List.copyOf(roles)));
        return Collections.unmodifiableMap(mappings);
    }

    /**
     * Merges mappings: every key from both maps, with the roles of both for keys that appear in each.
     * Keys are matched case-insensitively, as {@link EntraAuthorityMapper} does; the first spelling wins.
     */
    @SafeVarargs
    public static Map<String, List<String>> merge(Map<String, ? extends Collection<String>>... sources) {
        Map<String, String> spelling = new LinkedHashMap<>();
        Map<String, Set<String>> merged = new LinkedHashMap<>();
        for (Map<String, ? extends Collection<String>> source : sources) {
            if (source == null) {
                continue;
            }
            source.forEach((key, roles) -> {
                if (key == null || key.isBlank()) {
                    return;
                }
                String normalised = key.trim().toLowerCase(Locale.ROOT);
                String name = spelling.computeIfAbsent(normalised, k -> key.trim());
                Set<String> target = merged.computeIfAbsent(name, k -> new LinkedHashSet<>());
                if (roles != null) {
                    roles.stream().filter(r -> r != null && !r.isBlank()).map(String::trim).forEach(target::add);
                }
            });
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        merged.forEach((key, roles) -> result.put(key, new ArrayList<>(roles)));
        return result;
    }

    private static void validateKey(String property, int position, String entry, String key, KeyType keyType) {
        switch (keyType) {
            case APP_ROLE -> {
                if (WHITESPACE.matcher(key).find()) {
                    throw error(property, position, entry, "has app role '" + key + "' with whitespace in it");
                }
            }
            case CLIENT_ID -> {
                if (!GUID.matcher(key).matches()) {
                    throw error(property, position, entry, "has client id '" + key
                            + "', which is not a GUID; use the calling application's (client) ID");
                }
            }
            default -> {
                // group ids or names: any text
            }
        }
    }

    private static IllegalArgumentException error(String property, int position, String entry, String problem) {
        return new IllegalArgumentException(property + ": entry " + position + " '" + entry + "' " + problem);
    }
}
