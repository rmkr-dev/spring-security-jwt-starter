package io.github.rmkrdev.entra.security.core.outbound;

import java.io.IOException;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

/**
 * A {@code RestClient}/{@code RestTemplate} interceptor that picks the token for each request from the
 * configured routes, so one client can call several peers. Requests that already carry an
 * {@code Authorization} header, go to a skipped host or match no route are sent unchanged.
 */
public final class EntraRoutingInterceptor implements ClientHttpRequestInterceptor {

    private static final Logger log = LoggerFactory.getLogger(EntraRoutingInterceptor.class);

    private final OutboundRouter<ClientHttpRequestInterceptor> router;

    public EntraRoutingInterceptor(OutboundRouter<ClientHttpRequestInterceptor> router) {
        this.router = router;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        if (request.getHeaders().containsHeader(HttpHeaders.AUTHORIZATION)) {
            return execution.execute(request, body);
        }
        Optional<OutboundRouter.Route<ClientHttpRequestInterceptor>> route = router.route(request.getURI());
        if (route.isEmpty()) {
            log.trace("No Entra outbound route for {} {}", request.getMethod(), request.getURI().getHost());
            return execution.execute(request, body);
        }
        log.trace("Entra outbound route '{}' for {} {}", route.get().name(), request.getMethod(),
                request.getURI().getHost());
        return route.get().value().intercept(request, body, execution);
    }
}
