package io.github.rmkrdev.entra.security.core.authority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.springframework.security.core.GrantedAuthority;

/**
 * Role patterns that grant access to every authenticated API. A pattern is either a glob ({@code *hardware*},
 * {@code *} any characters, {@code ?} one character) or a Java regular expression prefixed with
 * {@code regex:}. Both must match the whole role name, which is tried with and without the {@code ROLE_} prefix.
 * Only role authorities are considered, never scopes.
 */
public final class AllowRolePatterns {

    private static final String ROLE_PREFIX = "ROLE_";

    private final List<Entry> patterns;

    /**
     * @param patterns      globs or {@code regex:} expressions
     * @param caseSensitive whether matching is case-sensitive
     * @throws IllegalArgumentException when a regular expression does not compile
     */
    public AllowRolePatterns(Collection<String> patterns, boolean caseSensitive) {
        List<Entry> compiled = new ArrayList<>();
        int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;
        for (String raw : patterns == null ? List.<String>of() : patterns) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            String value = raw.trim();
            try {
                Pattern pattern = value.regionMatches(true, 0, "regex:", 0, 6)
                        ? Pattern.compile(value.substring(6), flags) : Pattern.compile(glob(value), flags);
                compiled.add(new Entry(value, pattern));
            }
            catch (PatternSyntaxException ex) {
                throw new IllegalArgumentException("Invalid allow-role-pattern '" + value + "': "
                        + ex.getDescription(), ex);
            }
        }
        this.patterns = List.copyOf(compiled);
    }

    public boolean isEmpty() {
        return patterns.isEmpty();
    }

    /** The first role that matches a pattern, or empty. */
    public Optional<Match> match(Collection<? extends GrantedAuthority> authorities) {
        if (patterns.isEmpty() || authorities == null) {
            return Optional.empty();
        }
        for (GrantedAuthority authority : authorities) {
            String role = authority.getAuthority();
            if (role == null || !role.startsWith(ROLE_PREFIX)) {
                continue;
            }
            String name = role.substring(ROLE_PREFIX.length());
            for (Entry entry : patterns) {
                if (entry.pattern().matcher(name).matches() || entry.pattern().matcher(role).matches()) {
                    return Optional.of(new Match(role, entry.source()));
                }
            }
        }
        return Optional.empty();
    }

    static String glob(String glob) {
        StringBuilder regex = new StringBuilder();
        StringBuilder literal = new StringBuilder();
        for (char c : glob.toCharArray()) {
            if (c == '*' || c == '?') {
                if (literal.length() > 0) {
                    regex.append(Pattern.quote(literal.toString()));
                    literal.setLength(0);
                }
                regex.append(c == '*' ? ".*" : ".");
            }
            else {
                literal.append(c);
            }
        }
        if (literal.length() > 0) {
            regex.append(Pattern.quote(literal.toString()));
        }
        return regex.toString();
    }

    /**
     * @param role    the matching authority, for example {@code ROLE_HARDWARE_ADMIN}
     * @param pattern the configured pattern that matched
     */
    public record Match(String role, String pattern) {
    }

    private record Entry(String source, Pattern pattern) {
    }
}
