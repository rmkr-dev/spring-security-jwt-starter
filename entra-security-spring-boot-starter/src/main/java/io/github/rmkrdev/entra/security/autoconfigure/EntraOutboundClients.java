package io.github.rmkrdev.entra.security.autoconfigure;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.jwt.Jwt;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.OutboundFlow;
import io.github.rmkrdev.entra.security.core.outbound.EntraBearerTokenInterceptor;
import io.github.rmkrdev.entra.security.core.outbound.EntraOnBehalfOfInterceptor;
import io.github.rmkrdev.entra.security.core.outbound.EntraUserTokens;
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
 */
public class EntraOutboundClients {

    private final Map<String, Client> clients;

    public EntraOutboundClients(Map<String, Client> clients) {
        this.clients = Collections.unmodifiableMap(new LinkedHashMap<>(clients));
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
            return new EntraOnBehalfOfInterceptor(client.onBehalfOfTokenProvider(), client.scope());
        }
        return new EntraBearerTokenInterceptor(client.tokenProvider(), client.scope());
    }

    Client client(String name) {
        Client client = clients.get(name);
        if (client == null) {
            throw new IllegalArgumentException("No outbound client named '" + name + "' is configured under "
                    + "entra.security.outbound.clients (known: " + clients.keySet() + ")");
        }
        return client;
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
