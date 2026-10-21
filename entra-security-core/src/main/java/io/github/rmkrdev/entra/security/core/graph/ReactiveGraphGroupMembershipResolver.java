package io.github.rmkrdev.entra.security.core.graph;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import tools.jackson.databind.JsonNode;

import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Reactive counterpart of {@link GraphGroupMembershipResolver}: reads a user's transitive group memberships
 * from Microsoft Graph ({@code GET /v1.0/users/{oid}/transitiveMemberOf}) with a {@link WebClient}.
 * <p>
 * The same request, paging limit, filtering and error messages are used. The app-only token comes from an
 * {@link EntraTokenProvider}, which is called on {@link Schedulers#boundedElastic()} because a cache miss is
 * a blocking call to the token endpoint.
 */
public final class ReactiveGraphGroupMembershipResolver implements ReactiveGroupMembershipResolver {

    private final WebClient webClient;
    private final EntraTokenProvider tokenProvider;
    private final String baseUrl;
    private final String scope;
    private final int maxPages;
    private final Duration timeout;
    private final EntraSecurityObservations observations;

    /**
     * @param webClient     HTTP client used for Graph calls
     * @param tokenProvider app-only token source
     * @param graphBaseUrl  for example {@code https://graph.microsoft.com}
     * @param scope         for example {@code https://graph.microsoft.com/.default}
     * @param maxPages      upper bound on followed {@code @odata.nextLink} pages
     * @param timeout       per-page response timeout, or {@code null} for none
     * @param observations  notified for each lookup; {@code null} is treated as
     *                      {@link EntraSecurityObservations#NO_OP}
     */
    public ReactiveGraphGroupMembershipResolver(WebClient webClient, EntraTokenProvider tokenProvider,
            URI graphBaseUrl, String scope, int maxPages, Duration timeout, EntraSecurityObservations observations) {
        this.webClient = webClient;
        this.tokenProvider = tokenProvider;
        this.baseUrl = GraphPages.normalizeBaseUrl(graphBaseUrl.toString());
        this.scope = scope;
        this.maxPages = maxPages;
        this.timeout = timeout;
        this.observations = observations == null ? EntraSecurityObservations.NO_OP : observations;
    }

    @Override
    public Mono<List<GroupMembership>> resolve(String tenantId, String objectId) {
        return Mono.defer(() -> {
            long start = System.nanoTime();
            return lookup(objectId)
                    .doOnSuccess(groups -> observations.graphLookup(true, Duration.ofNanos(System.nanoTime() - start)))
                    .doOnError(ex -> observations.graphLookup(false, Duration.ofNanos(System.nanoTime() - start)));
        });
    }

    private Mono<List<GroupMembership>> lookup(String objectId) {
        return Mono.defer(() -> {
            List<GroupMembership> groups = new ArrayList<>();
            return page(GraphPages.firstPage(baseUrl, objectId), 1, groups).thenReturn(groups);
        });
    }

    private Mono<Void> page(String url, int number, List<GroupMembership> groups) {
        if (number > maxPages) {
            return Mono.error(GraphPages.tooManyPages(maxPages));
        }
        return fetch(url).flatMap(body -> {
            String next = GraphPages.collect(body, groups);
            return next == null ? Mono.<Void>empty() : page(next, number + 1, groups);
        });
    }

    private Mono<JsonNode> fetch(String url) {
        return Mono.fromCallable(() -> tokenProvider.getToken(scope).value())
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(token -> get(url, token));
    }

    private Mono<JsonNode> get(String url, String token) {
        Mono<JsonNode> body = webClient.get()
                .uri(URI.create(url))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .switchIfEmpty(Mono.error(() -> new GroupResolutionException("Graph returned an empty response")));
        if (timeout != null) {
            body = body.timeout(timeout);
        }
        return body
                .onErrorMap(WebClientResponseException.class, ex -> new GroupResolutionException(
                        "Graph group lookup failed with HTTP " + ex.getStatusCode().value(), ex))
                .onErrorMap(WebClientException.class,
                        ex -> new GroupResolutionException("Graph group lookup failed: " + ex.getMessage(), ex))
                .onErrorMap(TimeoutException.class,
                        ex -> new GroupResolutionException("Graph group lookup timed out after " + timeout, ex));
    }
}
