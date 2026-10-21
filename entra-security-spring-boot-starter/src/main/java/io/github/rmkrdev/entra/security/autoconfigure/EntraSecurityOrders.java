package io.github.rmkrdev.entra.security.autoconfigure;

import org.springframework.core.Ordered;

/**
 * Order of the filter chain Spring Boot installs when the application does not define one.
 * Boot 4 dropped {@code SecurityProperties.BASIC_AUTH_ORDER}; the chain is still
 * {@code Ordered.LOWEST_PRECEDENCE - 5}.
 */
final class EntraSecurityOrders {

    static final int FILTER_CHAIN = Ordered.LOWEST_PRECEDENCE - 5;

    private EntraSecurityOrders() {
    }
}
