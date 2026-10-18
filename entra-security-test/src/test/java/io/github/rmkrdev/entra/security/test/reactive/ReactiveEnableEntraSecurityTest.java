package io.github.rmkrdev.entra.security.test.reactive;

import static io.github.rmkrdev.entra.security.test.EntraWebTestClient.bearer;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.rmkrdev.entra.security.EnableEntraSecurity;
import io.github.rmkrdev.entra.security.EntraSecurityPreloader;
import io.github.rmkrdev.entra.security.test.AutoConfigureEntraMockAuthority;
import io.github.rmkrdev.entra.security.test.EntraTestTokens;
import reactor.core.publisher.Mono;

/**
 * {@code @EnableEntraSecurity} on a WebFlux application turns on reactive method security ({@code @Secured}
 * and {@code @PreAuthorize}) even when the property disables it, and preloads the signing keys.
 */
@SpringBootTest(classes = ReactiveEnableEntraSecurityTest.EnableApplication.class, properties = {
        "spring.main.web-application-type=reactive", "entra.security.method-security.enabled=false" })
@AutoConfigureWebTestClient
@AutoConfigureEntraMockAuthority
class ReactiveEnableEntraSecurityTest {

    static final String READERS = "aaaaaaaa-0000-0000-0000-000000000001";

    @Autowired
    WebTestClient client;

    @Autowired
    EntraTestTokens tokens;

    @Autowired
    EntraSecurityPreloader preloader;

    @Autowired
    ApplicationContext context;

    @Test
    void preloadsTheSigningKeys() {
        assertThat(preloader.getLoadedKeys()).isEqualTo(1);
    }

    @Test
    void enablesReactiveNotServletMethodSecurity() {
        assertThat(context.containsBean("entraReactiveSecuredAuthorizationMethodInterceptor")).isTrue();
        assertThat(context.containsBean("org.springframework.security.config.annotation.method.configuration."
                + "PrePostMethodSecurityConfiguration")).isFalse();
    }

    @Test
    void securedAndPreAuthorizeAreEnforced() {
        client.get().uri("/secured").headers(bearer(tokens.user().groups(READERS))).exchange()
                .expectStatus().isOk();
        client.get().uri("/secured").headers(bearer(tokens.user())).exchange()
                .expectStatus().isForbidden();
        client.get().uri("/pre-authorized").headers(bearer(tokens.user().groups(READERS))).exchange()
                .expectStatus().isOk();
        client.get().uri("/pre-authorized").headers(bearer(tokens.user())).exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("insufficient_scope");
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableEntraSecurity(failOnJwksError = true)
    @Import(Endpoints.class)
    static class EnableApplication {
    }

    @RestController
    static class Endpoints {

        @GetMapping("/secured")
        @Secured("ROLE_ORDERS_READ")
        Mono<String> secured() {
            return Mono.just("ok");
        }

        @GetMapping("/pre-authorized")
        @PreAuthorize("hasRole('ORDERS_READ')")
        Mono<String> preAuthorized() {
            return Mono.just("ok");
        }
    }
}
