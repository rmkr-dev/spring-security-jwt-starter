package io.github.rmkrdev.entra.sample;

import java.util.Map;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;

/**
 * Service-to-service endpoints, called by peer pods with app-only tokens.
 */
@RestController
@RequestMapping("/internal")
public class InternalController {

    @PostMapping("/orders/sync")
    @Secured("ROLE_ORDERS_SYNC")
    public Map<String, Object> sync(EntraPrincipal caller) {
        return Map.of("status", "accepted", "callerAppId", String.valueOf(caller.appId()));
    }
}
