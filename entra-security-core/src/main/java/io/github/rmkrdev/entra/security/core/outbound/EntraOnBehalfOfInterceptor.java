package io.github.rmkrdev.entra.security.core.outbound;

import java.io.IOException;
import java.util.function.Supplier;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.jwt.Jwt;

import io.github.rmkrdev.entra.security.core.token.EntraOnBehalfOfTokenProvider;

/**
 * Adds a downstream token acquired on behalf of the current user to outgoing {@code RestClient}/
 * {@code RestTemplate} requests. The user's token is taken from the {@code SecurityContextHolder}, so use it
 * on the request thread.
 * <p>
 * Throws {@link io.github.rmkrdev.entra.security.core.token.EntraInteractionRequiredException} when the user
 * has to consent or sign in again, and
 * {@link io.github.rmkrdev.entra.security.core.token.EntraTokenAcquisitionException} when there is no user
 * token or Entra refuses.
 */
public final class EntraOnBehalfOfInterceptor implements ClientHttpRequestInterceptor {

    private final EntraOnBehalfOfTokenProvider tokenProvider;
    private final String scope;
    private final Supplier<Jwt> userToken;
    private final boolean cae;

    public EntraOnBehalfOfInterceptor(EntraOnBehalfOfTokenProvider tokenProvider, String scope) {
        this(tokenProvider, scope, () -> EntraUserTokens.current().orElse(null));
    }

    /**
     * @param userToken supplies the incoming user token; {@code null} means there is none
     */
    public EntraOnBehalfOfInterceptor(EntraOnBehalfOfTokenProvider tokenProvider, String scope,
            Supplier<Jwt> userToken) {
        this(tokenProvider, scope, userToken, false);
    }

    /**
     * @param cae when {@code true}, a {@code 401} with an {@code insufficient_claims} challenge is answered once with
     *            a fresh token for the challenge claims
     */
    public EntraOnBehalfOfInterceptor(EntraOnBehalfOfTokenProvider tokenProvider, String scope,
            Supplier<Jwt> userToken, boolean cae) {
        this.cae = cae;
        this.tokenProvider = tokenProvider;
        this.scope = scope;
        this.userToken = userToken;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        Jwt jwt = userToken.get();
        if (jwt == null) {
            throw EntraUserTokens.missing();
        }
        request.getHeaders().setBearerAuth(tokenProvider.getToken(jwt, scope).value());
        ClientHttpResponse response = execution.execute(request, body);
        if (!cae) {
            return response;
        }
        return OutboundClaimsChallenge.retry(request, body, execution, response,
                claims -> tokenProvider.getToken(jwt, scope, claims));
    }
}
