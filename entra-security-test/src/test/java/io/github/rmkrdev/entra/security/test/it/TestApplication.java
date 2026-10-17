package io.github.rmkrdev.entra.security.test.it;

import java.util.Map;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;

/**
 * A consuming service with no security code, only {@code @Secured}.
 */
@SpringBootApplication
public class TestApplication {

    @RestController
    static class Endpoints {

        @GetMapping("/public/ping")
        String ping() {
            return "pong";
        }

        @GetMapping("/orders")
        @Secured("ROLE_ORDERS_READ")
        String orders() {
            return "orders";
        }

        @GetMapping("/admin")
        @Secured("ROLE_ADMIN")
        String admin() {
            return "admin";
        }

        @GetMapping("/internal/sync")
        @Secured("ROLE_SYNC")
        String sync() {
            return "synced";
        }

        @GetMapping("/internal/reports")
        @Secured("ROLE_REPORTS")
        String reports() {
            return "reports";
        }

        @GetMapping("/me")
        Map<String, Object> me(EntraPrincipal principal) {
            return Map.of("type", principal.type().name(), "oid", principal.objectId(), "appId",
                    String.valueOf(principal.appId()), "roles", principal.roles(), "version",
                    String.valueOf(principal.tokenVersion()));
        }
    }
}
