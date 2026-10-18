package io.github.rmkrdev.entra.sample.reactive;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * User-facing endpoints. Roles come from Entra groups or enterprise-app role assignments. Reactive method
 * security needs the methods to return a {@code Mono} or {@code Flux}.
 */
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @GetMapping
    @Secured("ROLE_ORDERS_READ")
    public Flux<Map<String, Object>> list() {
        return Flux.just(Map.of("id", 1, "item", "keyboard"), Map.of("id", 2, "item", "monitor"));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('ORDERS_WRITE')")
    public Mono<Map<String, Object>> create(@RequestBody Map<String, Object> order, EntraPrincipal principal) {
        return Mono.just(Map.of("item", order.getOrDefault("item", "unknown"), "createdBy", principal.getName()));
    }
}
