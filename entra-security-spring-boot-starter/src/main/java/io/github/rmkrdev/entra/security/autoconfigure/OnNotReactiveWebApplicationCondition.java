package io.github.rmkrdev.entra.security.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.NoneNestedConditions;

/**
 * Matches servlet and non-web applications, so the servlet beans keep working in plain application
 * contexts (and tests) while staying out of WebFlux applications.
 */
class OnNotReactiveWebApplicationCondition extends NoneNestedConditions {

    OnNotReactiveWebApplicationCondition() {
        super(ConfigurationPhase.PARSE_CONFIGURATION);
    }

    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    static class Reactive {
    }
}
