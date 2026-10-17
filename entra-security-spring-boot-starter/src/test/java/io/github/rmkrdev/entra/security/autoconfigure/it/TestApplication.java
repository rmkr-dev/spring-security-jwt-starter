package io.github.rmkrdev.entra.security.autoconfigure.it;

import java.util.Map;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;

/**
 * A consuming service: no security configuration at all, only annotations.
 */
@SpringBootApplication
public class TestApplication {

    @RestController
    static class TestController {

        @GetMapping("/public/ping")
        String ping() {
            return "pong";
        }

        @GetMapping("/orders")
        @Secured("ROLE_ORDERS_READ")
        String orders() {
            return "orders";
        }

        @PostMapping("/orders")
        @PreAuthorize("hasRole('ORDERS_WRITE')")
        String createOrder() {
            return "created";
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
        EntraPrincipal me(EntraPrincipal principal) {
            return principal;
        }

        @GetMapping("/me/annotated")
        Map<String, Object> annotated(@AuthenticationPrincipal EntraPrincipal principal) {
            return Map.of("type", principal.type().name(), "name", principal.getName());
        }
    }
}
