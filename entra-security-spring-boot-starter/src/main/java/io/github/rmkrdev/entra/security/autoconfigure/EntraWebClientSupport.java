package io.github.rmkrdev.entra.security.autoconfigure;

import java.util.ArrayList;
import java.util.List;

import org.springframework.web.reactive.function.client.ExchangeFilterFunction;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.OutboundFlow;
import io.github.rmkrdev.entra.security.core.outbound.EntraBearerExchangeFilterFunction;
import io.github.rmkrdev.entra.security.core.outbound.EntraOnBehalfOfExchangeFilterFunction;
import io.github.rmkrdev.entra.security.core.outbound.EntraRoutingExchangeFilterFunction;
import io.github.rmkrdev.entra.security.core.outbound.OutboundRouter;

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
            return new EntraOnBehalfOfExchangeFilterFunction(client.onBehalfOfTokenProvider(), client.scope(),
                    clients.isCae());
        }
        return new EntraBearerExchangeFilterFunction(client.tokenProvider(), client.scope(), clients.isCae());
    }

    /** The named client's filter with another scope. */
    public static ExchangeFilterFunction filter(EntraOutboundClients clients, String name, String scope) {
        EntraOutboundClients.Client client = clients.client(name);
        String effective = scope == null || scope.isBlank() ? client.scope() : scope;
        if (client.flow() == OutboundFlow.ON_BEHALF_OF) {
            return new EntraOnBehalfOfExchangeFilterFunction(client.onBehalfOfTokenProvider(), effective,
                    clients.isCae());
        }
        return new EntraBearerExchangeFilterFunction(client.tokenProvider(), effective, clients.isCae());
    }

    /**
     * An exchange filter that picks the client and scope for each request from
     * {@code entra.security.outbound.routes}. Requests that already have an {@code Authorization} header, go
     * to a skipped host or match no route are sent without a token.
     */
    public static ExchangeFilterFunction routingFilter(EntraOutboundClients clients) {
        List<OutboundRouter.Route<ExchangeFilterFunction>> routed = new ArrayList<>();
        for (EntraOutboundClients.Route route : clients.routes()) {
            routed.add(new OutboundRouter.Route<>(route.name(), route.targets(),
                    filter(clients, route.client(), route.scope())));
        }
        return new EntraRoutingExchangeFilterFunction(new OutboundRouter<>(routed, clients.skipHosts()));
    }
}
