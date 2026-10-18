package io.github.rmkrdev.entra.sample.reactive;

import java.util.Map;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import reactor.core.publisher.Mono;

/**
 * Service-to-service endpoints, called by peer pods with app-only tokens.
 */
@RestController
@RequestMapping("/internal")
public class InternalController {

    @PostMapping("/orders/sync")
    @Secured("ROLE_ORDERS_SYNC")
    public Mono<Map<String, Object>> sync(EntraPrincipal caller) {
        return Mono.just(Map.of("status", "accepted", "callerAppId", String.valueOf(caller.appId())));
    }
}
