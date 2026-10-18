package io.github.rmkrdev.entra.security.test.obo;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import io.github.rmkrdev.entra.security.autoconfigure.EntraOutboundClients;
import io.github.rmkrdev.entra.security.autoconfigure.EntraWebClientSupport;
import reactor.core.publisher.Mono;

/**
 * A WebFlux service that calls the downstream API as the signed-in user with {@code WebClient}.
 */
@SpringBootConfiguration
@EnableAutoConfiguration
@Import(OnBehalfOfReactiveApplication.ProfileController.class)
public class OnBehalfOfReactiveApplication {

    @RestController
    static class ProfileController {

        private final WebClient downstream;

        ProfileController(WebClient.Builder builder, EntraOutboundClients outbound) {
            this.downstream = builder.baseUrl(outbound.baseUrl("downstream"))
                    .filter(EntraWebClientSupport.filter(outbound, "downstream"))
                    .build();
        }

        @GetMapping("/profile/downstream-token")
        Mono<String> downstreamToken() {
            return downstream.get().uri("/token").retrieve().bodyToMono(String.class);
        }
    }
}
