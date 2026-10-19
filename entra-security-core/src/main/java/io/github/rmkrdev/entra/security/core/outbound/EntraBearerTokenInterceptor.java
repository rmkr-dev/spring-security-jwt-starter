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
    private final boolean cae;

    public EntraBearerTokenInterceptor(EntraTokenProvider tokenProvider, String scope) {
        this(tokenProvider, scope, false);
    }

    /**
     * @param cae when {@code true}, a {@code 401} with an {@code insufficient_claims} challenge is answered once with
     *            a fresh token for the challenge claims
     */
    public EntraBearerTokenInterceptor(EntraTokenProvider tokenProvider, String scope, boolean cae) {
        this.tokenProvider = tokenProvider;
        this.scope = scope;
        this.cae = cae;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        request.getHeaders().setBearerAuth(tokenProvider.getToken(scope).value());
        ClientHttpResponse response = execution.execute(request, body);
        if (!cae) {
            return response;
        }
        return OutboundClaimsChallenge.retry(request, body, execution, response,
                claims -> tokenProvider.getToken(scope, claims));
    }
}
