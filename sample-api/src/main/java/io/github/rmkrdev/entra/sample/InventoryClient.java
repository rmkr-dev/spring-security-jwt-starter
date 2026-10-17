package io.github.rmkrdev.entra.sample;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import io.github.rmkrdev.entra.security.autoconfigure.EntraOutboundClients;

/**
 * Calls a peer API with an app-only token acquired through the configured credential
 * (client secret, certificate or AKS workload identity).
 */
@Component
@ConditionalOnProperty(prefix = "entra.security.outbound.clients.inventory-api", name = "scope")
public class InventoryClient {

    private final RestClient restClient;

    public InventoryClient(RestClient.Builder builder, EntraOutboundClients outbound) {
        this.restClient = builder
                .baseUrl(outbound.baseUrl("inventory-api"))
                .requestInterceptor(outbound.interceptor("inventory-api"))
                .build();
    }

    public String stockLevel(String sku) {
        return restClient.get().uri("/api/stock/{sku}", sku).retrieve().body(String.class);
    }
}
