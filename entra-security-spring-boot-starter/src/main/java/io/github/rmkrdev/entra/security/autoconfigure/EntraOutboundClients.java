package io.github.rmkrdev.entra.security.autoconfigure;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.http.client.ClientHttpRequestInterceptor;

import io.github.rmkrdev.entra.security.core.outbound.EntraBearerTokenInterceptor;
import io.github.rmkrdev.entra.security.core.token.AccessToken;
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
 * For {@code WebClient}, use {@link EntraWebClientSupport#filter(EntraOutboundClients, String)}.
 */
public class EntraOutboundClients {

    private final Map<String, Client> clients;

    public EntraOutboundClients(Map<String, Client> clients) {
        this.clients = Collections.unmodifiableMap(new LinkedHashMap<>(clients));
    }

    public Set<String> names() {
        return clients.keySet();
    }

    /** The token provider of a named client. */
    public EntraTokenProvider tokenProvider(String name) {
        return client(name).tokenProvider();
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

    /** Acquires (or returns a cached) token for a named client. */
    public AccessToken token(String name) {
        Client client = client(name);
        return client.tokenProvider().getToken(client.scope());
    }

    /** A {@code RestClient}/{@code RestTemplate} interceptor that adds the named client's bearer token. */
    public ClientHttpRequestInterceptor interceptor(String name) {
        Client client = client(name);
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
     * @param name          the configuration key
     * @param scope         the requested scope
     * @param baseUrl       optional base URL
     * @param tokenProvider token source
     */
    public record Client(String name, String scope, URI baseUrl, EntraTokenProvider tokenProvider) {
    }
}
