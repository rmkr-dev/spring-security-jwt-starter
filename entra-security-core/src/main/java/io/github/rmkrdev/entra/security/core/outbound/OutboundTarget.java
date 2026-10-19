package io.github.rmkrdev.entra.security.core.outbound;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import org.springframework.util.AntPathMatcher;

/**
 * Which outgoing requests an outbound route applies to: a host pattern, an optional port, the allowed
 * schemes and Ant-style path patterns.
 * <p>
 * Host patterns are case-insensitive. A pattern is an exact host ({@code example.text.com}), a
 * subdomain wildcard ({@code *.shop.svc.cluster.local}, matching any host below it but not
 * {@code shop.svc.cluster.local} itself) or {@code *} for any host. An optional {@code :port} restricts
 * the port.
 * <p>
 * By default only {@code https} matches. Plain {@code http} also matches for in-cluster service names
 * ({@code *.svc}, {@code *.svc.cluster.local}) and loopback hosts, where traffic stays inside the cluster
 * or the machine, or when {@code http} is allowed explicitly.
 */
public final class OutboundTarget {

    private static final AntPathMatcher PATHS = new AntPathMatcher();

    private final String host;
    private final boolean subdomains;
    private final int port;
    private final String scheme;
    private final Boolean allowHttp;
    private final List<String> paths;

    private OutboundTarget(String host, boolean subdomains, int port, String scheme, Boolean allowHttp,
            List<String> paths) {
        this.host = host;
        this.subdomains = subdomains;
        this.port = port;
        this.scheme = scheme;
        this.allowHttp = allowHttp;
        this.paths = paths.isEmpty() ? List.of("/**") : List.copyOf(paths);
    }

    /**
     * A target from a URL pattern such as {@code https://example.text.com/api/**} or
     * {@code http://*.shop.svc.cluster.local:8080/**}. The scheme is matched exactly; a pattern without a
     * path matches every path.
     *
     * @throws IllegalArgumentException when the pattern is not a valid URL pattern
     */
    public static OutboundTarget url(String pattern) {
        Objects.requireNonNull(pattern, "pattern");
        int separator = pattern.indexOf("://");
        if (separator <= 0) {
            throw new IllegalArgumentException("URL pattern '" + pattern + "' must start with http:// or https://");
        }
        String scheme = pattern.substring(0, separator).toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new IllegalArgumentException("URL pattern '" + pattern + "' must start with http:// or https://");
        }
        String rest = pattern.substring(separator + 3);
        int slash = rest.indexOf('/');
        String authority = slash < 0 ? rest : rest.substring(0, slash);
        String path = slash < 0 ? "/**" : rest.substring(slash);
        if (path.contains("?") || path.contains("#")) {
            throw new IllegalArgumentException("URL pattern '" + pattern + "' must not contain a query or fragment");
        }
        return parse(pattern, authority, scheme, null, List.of(path));
    }

    /**
     * A target from a host pattern with an optional {@code :port}, such as {@code *.svc.cluster.local} or
     * {@code partner.example.test:8443}.
     *
     * @param allowHttp {@code true} or {@code false} to allow or refuse plain http; {@code null} allows it
     *                  only for in-cluster and loopback hosts
     * @param paths     Ant-style path patterns; empty matches every path
     * @throws IllegalArgumentException when the host pattern is invalid
     */
    public static OutboundTarget host(String hostPattern, Boolean allowHttp, List<String> paths) {
        Objects.requireNonNull(hostPattern, "hostPattern");
        for (String path : paths) {
            if (path == null || !path.startsWith("/")) {
                throw new IllegalArgumentException("Path pattern '" + path + "' must start with /");
            }
        }
        return parse(hostPattern, hostPattern, null, allowHttp, paths);
    }

    private static OutboundTarget parse(String source, String authority, String scheme, Boolean allowHttp,
            List<String> paths) {
        String hostPart = authority;
        int port = -1;
        int colon = authority.lastIndexOf(':');
        if (colon >= 0 && !authority.endsWith("]")) {
            hostPart = authority.substring(0, colon);
            try {
                port = Integer.parseInt(authority.substring(colon + 1));
            }
            catch (NumberFormatException ex) {
                throw new IllegalArgumentException("'" + source + "' has an invalid port");
            }
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("'" + source + "' has an invalid port");
            }
        }
        String host = hostPart.toLowerCase(Locale.ROOT);
        boolean subdomains = false;
        if (host.startsWith("*.")) {
            subdomains = true;
            host = host.substring(2);
        }
        if (host.isEmpty() || host.contains("/") || host.contains("@")
                || (host.contains("*") && !host.equals("*"))) {
            throw new IllegalArgumentException("'" + source + "' must name a host, *.domain or *; '*' is only "
                    + "allowed as the first label");
        }
        if (subdomains && host.equals("*")) {
            throw new IllegalArgumentException("'" + source + "' must name a host, *.domain or *");
        }
        return new OutboundTarget(host, subdomains, port, scheme, allowHttp, paths);
    }

    /** Whether the request URI is covered by this target. */
    public boolean matches(URI uri) {
        if (uri == null || uri.getHost() == null || uri.getScheme() == null) {
            return false;
        }
        String requestScheme = uri.getScheme().toLowerCase(Locale.ROOT);
        String requestHost = normalizeHost(uri.getHost());
        if (!hostMatches(requestHost)) {
            return false;
        }
        if (port > 0 && port != effectivePort(uri)) {
            return false;
        }
        if (!schemeMatches(requestScheme, requestHost)) {
            return false;
        }
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        for (String pattern : paths) {
            if (PATHS.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    /** Whether the host (and port, when the pattern has one) of the request matches, ignoring scheme and path. */
    public boolean matchesHost(URI uri) {
        if (uri == null || uri.getHost() == null) {
            return false;
        }
        return hostMatches(normalizeHost(uri.getHost())) && (port <= 0 || port == effectivePort(uri));
    }

    private boolean hostMatches(String requestHost) {
        if (host.equals("*")) {
            return true;
        }
        if (subdomains) {
            return requestHost.endsWith("." + host);
        }
        return requestHost.equals(host);
    }

    private boolean schemeMatches(String requestScheme, String requestHost) {
        if (scheme != null) {
            return scheme.equals(requestScheme);
        }
        if (requestScheme.equals("https")) {
            return true;
        }
        if (!requestScheme.equals("http")) {
            return false;
        }
        return allowHttp != null ? allowHttp : isInternal(requestHost);
    }

    /** Whether a host is an in-cluster service name or a loopback address. */
    public static boolean isInternal(String host) {
        String h = normalizeHost(host);
        return h.endsWith(".svc") || h.endsWith(".svc.cluster.local") || h.equals("localhost")
                || h.equals("127.0.0.1") || h.equals("::1");
    }

    private static String normalizeHost(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        return h.endsWith(".") ? h.substring(0, h.length() - 1) : h;
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() > 0) {
            return uri.getPort();
        }
        return "http".equalsIgnoreCase(uri.getScheme()) ? 80 : 443;
    }

    @Override
    public String toString() {
        return (scheme == null ? "" : scheme + "://") + (subdomains ? "*." : "") + host
                + (port > 0 ? ":" + port : "") + paths;
    }
}
