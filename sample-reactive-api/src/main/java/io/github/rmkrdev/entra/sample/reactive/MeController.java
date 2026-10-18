package io.github.rmkrdev.entra.sample.reactive;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import reactor.core.publisher.Mono;

/**
 * Returns the authenticated caller, user or service.
 */
@RestController
public class MeController {

    @GetMapping("/api/me")
    public Mono<EntraPrincipal> me(Mono<EntraPrincipal> principal) {
        return principal;
    }
}
