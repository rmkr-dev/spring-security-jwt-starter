package io.github.rmkrdev.entra.security.autoconfigure;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.jwt.Jwt;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.OutboundFlow;
import io.github.rmkrdev.entra.security.core.outbound.EntraBearerTokenInterceptor;
import io.github.rmkrdev.entra.security.core.outbound.EntraOnBehalfOfInterceptor;
import io.github.rmkrdev.entra.security.core.outbound.EntraRoutingInterceptor;
import io.github.rmkrdev.entra.security.core.outbound.EntraUserTokens;
import io.github.rmkrdev.entra.security.core.outbound.OutboundRouter;
import io.github.rmkrdev.entra.security.core.outbound.OutboundTarget;
import io.github.rmkrdev.entra.security.core.token.AccessToken;
import io.github.rmkrdev.entra.security.core.token.EntraOnBehalfOfTokenProvider;
import io.github.rmkrdev.entra.security.core.token.EntraTokenAcquisitionException;
import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;

/**
 * The outbound clients configured under {@code entra.security.outbound.clients}.
 * <p>
 * Typical use:
 *
 * <pre>{@code
 * RestClient orders = restClientBuilder
 *         .baseUrl(outbound.baseUrl("orders-api"))
 *         .requestInterceptor(outbound.interceptor("orders-api"))
 *         .build();
 * }</pre>
 *
 * The interceptor follows the client's {@code flow}: an app-only token for {@code client-credentials}, or a
 * token for the current user for {@code on-behalf-of}. For {@code WebClient}, use
 * {@link EntraWebClientSupport#filter(EntraOutboundClients, String)}.
 * <p>
 * With {@code entra.security.outbound.routes}, one client can call several peers: the
 * {@link #routingInterceptor()} (or {@link EntraWebClientSupport#routingFilter(EntraOutboundClients)}) picks
 * the client and scope for each request by URL or host. Spring Boot's {@code RestClient.Builder} and
 * {@code WebClient.Builder} get it automatically unless {@code outbound.customize-builders=false}.
 */
public class EntraOutboundClients {

    private final Map<String, Client> clients;
    private final List<Route> routes;
    private final List<OutboundTarget> skipHosts;
    private boolean cae;

    public EntraOutboundClients(Map<String, Client> clients) {
        this(clients, List.of(), List.of());
    }

    /**
     * @param routes    routes that map requests to clients, first match wins
     * @param skipHosts hosts that never get a token from the routes
     */
    public EntraOutboundClients(Map<String, Client> clients, List<Route> routes, List<OutboundTarget> skipHosts) {
        Map<String, Client> registered = Collections.unmodifiableMap(new LinkedHashMap<>(clients));
        for (Route route : routes) {
            requireClient(registered, route.client());
        }
        this.clients = registered;
        this.routes = List.copyOf(routes);
        this.skipHosts = List.copyOf(skipHosts);
    }

    /**
     * Answer {@code insufficient_claims} challenges from downstream APIs once with a fresh token
     * ({@code entra.security.cae.enabled}).
     *
     * @return this
     */
    public EntraOutboundClients withCae(boolean cae) {
        this.cae = cae;
        return this;
    }

    public boolean isCae() {
        return cae;
    }

    public Set<String> names() {
        return clients.keySet();
    }

    /** The token flow of a named client. */
    public OutboundFlow flow(String name) {
        return client(name).flow();
    }

    /**
     * The app-only token provider of a named client.
     *
     * @throws IllegalStateException when the client uses the on-behalf-of flow
     */
    public EntraTokenProvider tokenProvider(String name) {
        Client client = client(name);
        if (client.tokenProvider() == null) {
            throw new IllegalStateException("Outbound client '" + name + "' uses flow on-behalf-of; use "
                    + "onBehalfOfTokenProvider(\"" + name + "\") or token(\"" + name + "\")");
        }
        return client.tokenProvider();
    }

    /**
     * The on-behalf-of token provider of a named client.
     *
     * @throws IllegalStateException when the client uses the client-credentials flow
     */
    public EntraOnBehalfOfTokenProvider onBehalfOfTokenProvider(String name) {
        Client client = client(name);
        if (client.onBehalfOfTokenProvider() == null) {
            throw new IllegalStateException("Outbound client '" + name + "' uses flow client-credentials; set "
                    + "entra.security.outbound.clients." + name + ".flow=on-behalf-of to call it as the user");
        }
        return client.onBehalfOfTokenProvider();
    }

    /** The scope of a named client. */
    public String scope(String name) {
        return client(name).scope();
    }

    /** The configured base URL of a named client, or {@code null}. */
    public String baseUrl(String name) {
        URI baseUrl = client(name).baseUrl();
        return baseUrl == null ? null : baseUrl.toString();
    }

    /**
     * Acquires (or returns a cached) token for a named client. For an on-behalf-of client the user token
     * is taken from the current thread's security context.
     */
    public AccessToken token(String name) {
        Client client = client(name);
        if (client.flow() == OutboundFlow.ON_BEHALF_OF) {
            Jwt userToken = EntraUserTokens.current().orElseThrow(() -> new EntraTokenAcquisitionException(
                    "Outbound client '" + name + "' calls on behalf of the user, but the security context holds no "
                            + "user token", "invalid_request", null));
            return token(name, userToken);
        }
        return client.tokenProvider().getToken(client.scope());
    }

    /** Acquires (or returns a cached) token for an on-behalf-of client and the given user token. */
    public AccessToken token(String name, Jwt userToken) {
        Client client = client(name);
        return onBehalfOfTokenProvider(name).getToken(userToken, client.scope());
    }

    /**
     * A {@code RestClient}/{@code RestTemplate} interceptor that adds the named client's bearer token: app-only,
     * or on behalf of the current user.
     */
    public ClientHttpRequestInterceptor interceptor(String name) {
        Client client = client(name);
        if (client.flow() == OutboundFlow.ON_BEHALF_OF) {
            return new EntraOnBehalfOfInterceptor(client.onBehalfOfTokenProvider(), client.scope(),
                    () -> EntraUserTokens.current().orElse(null), cae);
        }
        return new EntraBearerTokenInterceptor(client.tokenProvider(), client.scope(), cae);
    }

    /**
     * The same interceptor with another scope, for example a narrower scope of the same peer.
     */
    public ClientHttpRequestInterceptor interceptor(String name, String scope) {
        Client client = client(name);
        String effective = scope == null || scope.isBlank() ? client.scope() : scope;
        if (client.flow() == OutboundFlow.ON_BEHALF_OF) {
            return new EntraOnBehalfOfInterceptor(client.onBehalfOfTokenProvider(), effective,
                    () -> EntraUserTokens.current().orElse(null), cae);
        }
        return new EntraBearerTokenInterceptor(client.tokenProvider(), effective, cae);
    }

    /** The configured routes, in order. */
    public List<Route> routes() {
        return routes;
    }

    /** Whether any routes are configured. */
    public boolean hasRoutes() {
        return !routes.isEmpty();
    }

    /**
     * A {@code RestClient}/{@code RestTemplate} interceptor that picks the client and scope for each request
     * from {@code entra.security.outbound.routes}. Requests that already have an {@code Authorization}
     * header, go to a skipped host or match no route are sent without a token.
     */
    public ClientHttpRequestInterceptor routingInterceptor() {
        List<OutboundRouter.Route<ClientHttpRequestInterceptor>> routed = new ArrayList<>();
        for (Route route : routes) {
            routed.add(new OutboundRouter.Route<>(route.name(), route.targets(),
                    interceptor(route.client(), route.scope())));
        }
        return new EntraRoutingInterceptor(new OutboundRouter<>(routed, skipHosts));
    }

    /** The hosts that never get a token from the routes. */
    List<OutboundTarget> skipHosts() {
        return skipHosts;
    }

    Client client(String name) {
        return requireClient(clients, name);
    }

    private static Client requireClient(Map<String, Client> clients, String name) {
        Client client = clients.get(name);
        if (client == null) {
            throw new IllegalArgumentException("No outbound client named '" + name + "' is configured under "
                    + "entra.security.outbound.clients (known: " + clients.keySet() + ")");
        }
        return client;
    }

    /**
     * A route from requests to an outbound client.
     *
     * @param name    used in log messages
     * @param targets the requests it applies to
     * @param client  the outbound client name
     * @param scope   the scope to request, or {@code null} for the client's scope
     */
    public record Route(String name, List<OutboundTarget> targets, String client, String scope) {

        public Route {
            targets = List.copyOf(targets);
        }
    }

    /**
     * A configured outbound client.
     *
     * @param name                    the configuration key
     * @param scope                   the requested scope
     * @param baseUrl                 optional base URL
     * @param flow                    how tokens are acquired
     * @param tokenProvider           app-only token source, for {@code client-credentials}
     * @param onBehalfOfTokenProvider user token exchange, for {@code on-behalf-of}
     */
    public record Client(String name, String scope, URI baseUrl, OutboundFlow flow, EntraTokenProvider tokenProvider,
            EntraOnBehalfOfTokenProvider onBehalfOfTokenProvider) {

        /** A client-credentials client. */
        public Client(String name, String scope, URI baseUrl, EntraTokenProvider tokenProvider) {
            this(name, scope, baseUrl, OutboundFlow.CLIENT_CREDENTIALS, tokenProvider, null);
        }

        /** An on-behalf-of client. */
        public static Client onBehalfOf(String name, String scope, URI baseUrl,
                EntraOnBehalfOfTokenProvider tokenProvider) {
            return new Client(name, scope, baseUrl, OutboundFlow.ON_BEHALF_OF, null, tokenProvider);
        }
    }
}
