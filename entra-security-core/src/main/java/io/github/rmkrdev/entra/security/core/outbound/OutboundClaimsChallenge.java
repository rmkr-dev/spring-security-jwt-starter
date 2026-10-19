package io.github.rmkrdev.entra.security.core.outbound;

import java.io.IOException;
import java.util.Optional;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;

import io.github.rmkrdev.entra.security.core.cae.ContinuousAccessEvaluation;
import io.github.rmkrdev.entra.security.core.token.AccessToken;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Answers a downstream {@code 401} with an {@code insufficient_claims} challenge by getting a token for the
 * challenge claims and sending the request once more. Any other response, and the second response, are returned
 * as they are.
 */
final class OutboundClaimsChallenge {

    private static final Logger log = LoggerFactory.getLogger(OutboundClaimsChallenge.class);

    private OutboundClaimsChallenge() {
    }

    static ClientHttpResponse retry(HttpRequest request, byte[] body, ClientHttpRequestExecution execution,
            ClientHttpResponse response, Function<String, AccessToken> tokenForClaims) throws IOException {
        Optional<String> claims = challenge(response.getStatusCode().value(),
                response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE));
        if (claims.isEmpty()) {
            return response;
        }
        response.close();
        log.debug("Claims challenge from {}; retrying once with a new token", request.getURI().getHost());
        request.getHeaders().setBearerAuth(tokenForClaims.apply(claims.get()).value());
        return execution.execute(request, body);
    }

    static Mono<ClientResponse> retry(ClientRequest request, ExchangeFunction next, ClientResponse response,
            Function<String, AccessToken> tokenForClaims) {
        Optional<String> claims = challenge(response.statusCode().value(),
                response.headers().asHttpHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE));
        if (claims.isEmpty()) {
            return Mono.just(response);
        }
        log.debug("Claims challenge from {}; retrying once with a new token", request.url().getHost());
        return response.releaseBody()
                .then(Mono.fromCallable(() -> tokenForClaims.apply(claims.get()))
                        .subscribeOn(Schedulers.boundedElastic()))
                .flatMap(token -> next.exchange(withToken(request, token)));
    }

    static ClientRequest withToken(ClientRequest request, AccessToken token) {
        return ClientRequest.from(request).headers(headers -> headers.setBearerAuth(token.value())).build();
    }

    private static Optional<String> challenge(int status, String wwwAuthenticate) {
        if (status != HttpStatus.UNAUTHORIZED.value()) {
            return Optional.empty();
        }
        return ContinuousAccessEvaluation.claimsChallenge(wwwAuthenticate);
    }
}
