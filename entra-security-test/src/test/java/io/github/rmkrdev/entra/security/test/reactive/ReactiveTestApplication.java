package io.github.rmkrdev.entra.security.test.reactive;

import java.util.Map;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import io.github.rmkrdev.entra.security.core.principal.ReactiveEntraPrincipals;
import reactor.core.publisher.Mono;

/**
 * A WebFlux service: no security configuration, only annotations. Tests run it with
 * {@code spring.main.web-application-type=reactive}.
 */
@SpringBootApplication
public class ReactiveTestApplication {

    @RestController
    static class Endpoints {

        @GetMapping("/public/ping")
        Mono<String> ping() {
            return Mono.just("pong");
        }

        @GetMapping("/public/whoami")
        Mono<String> whoami(EntraPrincipal principal) {
            return Mono.just(principal == null ? "anonymous" : principal.objectId());
        }

        @GetMapping("/orders")
        @Secured("ROLE_ORDERS_READ")
        Mono<String> orders() {
            return Mono.just("orders");
        }

        @PostMapping("/orders")
        @PreAuthorize("hasRole('ORDERS_WRITE')")
        Mono<String> createOrder() {
            return Mono.just("created");
        }

        @GetMapping("/admin")
        @Secured("ROLE_ADMIN")
        Mono<String> admin() {
            return Mono.just("admin");
        }

        @GetMapping("/internal/sync")
        @Secured("ROLE_SYNC")
        Mono<String> sync() {
            return Mono.just("synced");
        }

        @GetMapping("/internal/reports")
        @PreAuthorize("hasRole('REPORTS')")
        Mono<String> reports() {
            return Mono.just("reports");
        }

        @GetMapping("/me")
        Mono<Map<String, Object>> me(EntraPrincipal principal) {
            return Mono.just(Map.of("type", principal.type().name(), "oid", principal.objectId(), "appId",
                    String.valueOf(principal.appId()), "roles", principal.roles(), "groups", principal.groups(),
                    "version", String.valueOf(principal.tokenVersion())));
        }

        @GetMapping("/me/mono")
        Mono<String> mono(Mono<EntraPrincipal> principal) {
            return principal.map(EntraPrincipal::objectId);
        }

        @GetMapping("/me/annotated")
        Mono<String> annotated(@AuthenticationPrincipal EntraPrincipal principal) {
            return Mono.just(principal.type().name());
        }

        @GetMapping("/me/current")
        Mono<String> current() {
            return ReactiveEntraPrincipals.require().map(EntraPrincipal::objectId);
        }
    }
}
