package io.github.rmkrdev.entra.security.test.obo;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import io.github.rmkrdev.entra.security.autoconfigure.EntraOutboundClients;

/**
 * A Spring MVC service that calls the downstream API as the signed-in user with {@code RestClient}.
 */
@SpringBootConfiguration
@EnableAutoConfiguration
@Import(OnBehalfOfServletApplication.ProfileController.class)
public class OnBehalfOfServletApplication {

    @RestController
    static class ProfileController {

        private final RestClient downstream;

        ProfileController(RestClient.Builder builder, EntraOutboundClients outbound) {
            this.downstream = builder.baseUrl(outbound.baseUrl("downstream"))
                    .requestInterceptor(outbound.interceptor("downstream"))
                    .build();
        }

        @GetMapping("/profile/downstream-token")
        String downstreamToken() {
            return downstream.get().uri("/token").retrieve().body(String.class);
        }
    }
}
