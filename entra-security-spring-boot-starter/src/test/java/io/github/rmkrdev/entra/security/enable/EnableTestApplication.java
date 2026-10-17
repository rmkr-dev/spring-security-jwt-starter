package io.github.rmkrdev.entra.security.enable;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.rmkrdev.entra.security.EnableEntraSecurity;

@SpringBootApplication
@EnableEntraSecurity(failOnJwksError = true)
public class EnableTestApplication {

    @RestController
    static class Controller {

        @GetMapping("/secured")
        @Secured("ROLE_ORDERS_READ")
        String secured() {
            return "ok";
        }
    }
}
