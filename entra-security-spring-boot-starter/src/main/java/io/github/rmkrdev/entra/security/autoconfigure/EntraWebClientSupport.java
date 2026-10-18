package io.github.rmkrdev.entra.security.autoconfigure;

import org.springframework.web.reactive.function.client.ExchangeFilterFunction;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.OutboundFlow;
import io.github.rmkrdev.entra.security.core.outbound.EntraBearerExchangeFilterFunction;
import io.github.rmkrdev.entra.security.core.outbound.EntraOnBehalfOfExchangeFilterFunction;

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
     * <p>
     * For an on-behalf-of client the user token is read from the Reactor context on WebFlux, or from the
     * subscribing thread's security context in a servlet application.
     */
    public static ExchangeFilterFunction filter(EntraOutboundClients clients, String name) {
        EntraOutboundClients.Client client = clients.client(name);
        if (client.flow() == OutboundFlow.ON_BEHALF_OF) {
            return new EntraOnBehalfOfExchangeFilterFunction(client.onBehalfOfTokenProvider(), client.scope());
        }
        return new EntraBearerExchangeFilterFunction(client.tokenProvider(), client.scope());
    }
}
