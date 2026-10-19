package io.github.rmkrdev.entra.security.core.outbound;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Picks the outbound route for a request URI: hosts listed in {@code skipHosts} never get a route, otherwise
 * the first route with a matching target wins. No match means the request is sent without an Entra token.
 *
 * @param <T> what a route carries, for example a request interceptor
 */
public final class OutboundRouter<T> {

    private final List<Route<T>> routes;
    private final List<OutboundTarget> skipHosts;

    public OutboundRouter(List<Route<T>> routes, List<OutboundTarget> skipHosts) {
        this.routes = List.copyOf(routes);
        this.skipHosts = List.copyOf(skipHosts);
    }

    /** The route for a request, or empty when the host is skipped or no route matches. */
    public Optional<Route<T>> route(URI uri) {
        if (isSkipped(uri)) {
            return Optional.empty();
        }
        for (Route<T> route : routes) {
            if (route.matches(uri)) {
                return Optional.of(route);
            }
        }
        return Optional.empty();
    }

    /** Whether the request host is listed in the skip hosts. */
    public boolean isSkipped(URI uri) {
        for (OutboundTarget skip : skipHosts) {
            if (skip.matchesHost(uri)) {
                return true;
            }
        }
        return false;
    }

    public List<Route<T>> routes() {
        return routes;
    }

    /**
     * A named route.
     *
     * @param name    used in log messages
     * @param targets the requests it applies to
     * @param value   what the route does, for example the interceptor that adds the token
     */
    public record Route<T>(String name, List<OutboundTarget> targets, T value) {

        public Route {
            Objects.requireNonNull(name, "name");
            targets = List.copyOf(targets);
            Objects.requireNonNull(value, "value");
        }

        boolean matches(URI uri) {
            for (OutboundTarget target : targets) {
                if (target.matches(uri)) {
                    return true;
                }
            }
            return false;
        }
    }
}
