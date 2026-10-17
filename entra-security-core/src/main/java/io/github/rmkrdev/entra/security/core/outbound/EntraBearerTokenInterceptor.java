package io.github.rmkrdev.entra.security.core.outbound;

import java.io.IOException;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;

/**
 * Adds an app-only Entra bearer token to outgoing {@code RestClient}/{@code RestTemplate} requests.
 */
public final class EntraBearerTokenInterceptor implements ClientHttpRequestInterceptor {

    private final EntraTokenProvider tokenProvider;
    private final String scope;

    public EntraBearerTokenInterceptor(EntraTokenProvider tokenProvider, String scope) {
        this.tokenProvider = tokenProvider;
        this.scope = scope;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        request.getHeaders().setBearerAuth(tokenProvider.getToken(scope).value());
        return execution.execute(request, body);
    }
}
