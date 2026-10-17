package io.github.rmkrdev.entra.sample;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;

/**
 * Returns the authenticated caller, user or service.
 */
@RestController
public class MeController {

    @GetMapping("/api/me")
    public EntraPrincipal me(EntraPrincipal principal) {
        return principal;
    }
}
