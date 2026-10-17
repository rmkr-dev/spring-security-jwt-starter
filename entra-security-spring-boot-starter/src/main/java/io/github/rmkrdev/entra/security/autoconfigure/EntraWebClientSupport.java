package io.github.rmkrdev.entra.security.autoconfigure;

import org.springframework.web.reactive.function.client.ExchangeFilterFunction;

import io.github.rmkrdev.entra.security.core.outbound.EntraBearerExchangeFilterFunction;

/**
 * {@code WebClient} support for outbound clients. Kept separate from {@link EntraOutboundClients} so
 * WebFlux stays optional.
 */
public final class EntraWebClientSupport {

    private EntraWebClientSupport() {
    }

    /**
     * An exchange filter that adds the named client's bearer token:
     * {@code WebClient.builder().filter(EntraWebClientSupport.filter(outbound, "orders-api"))}.
     */
    public static ExchangeFilterFunction filter(EntraOutboundClients clients, String name) {
        EntraOutboundClients.Client client = clients.client(name);
        return new EntraBearerExchangeFilterFunction(client.tokenProvider(), client.scope());
    }
}
