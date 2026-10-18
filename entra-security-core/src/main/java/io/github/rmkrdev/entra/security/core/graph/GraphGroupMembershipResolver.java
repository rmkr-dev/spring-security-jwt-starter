package io.github.rmkrdev.entra.security.core.graph;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import com.fasterxml.jackson.databind.JsonNode;

import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;

/**
 * Reads a user's transitive group memberships from Microsoft Graph
 * ({@code GET /v1.0/users/{oid}/transitiveMemberOf}) using an app-only token.
 * <p>
 * Requires the {@code GroupMember.Read.All} (or {@code Directory.Read.All}) application permission.
 */
public final class GraphGroupMembershipResolver implements GroupMembershipResolver {

    private static final Pattern GUID = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final String GROUP_TYPE = "#microsoft.graph.group";

    private final RestClient restClient;
    private final EntraTokenProvider tokenProvider;
    private final String baseUrl;
    private final String scope;
    private final int maxPages;
    private final EntraSecurityObservations observations;

    /**
     * @param restClient    HTTP client used for Graph calls
     * @param tokenProvider app-only token source
     * @param graphBaseUrl  for example {@code https://graph.microsoft.com}
     * @param scope         for example {@code https://graph.microsoft.com/.default}
     * @param maxPages      upper bound on followed {@code @odata.nextLink} pages
     */
    public GraphGroupMembershipResolver(RestClient restClient, EntraTokenProvider tokenProvider, URI graphBaseUrl,
            String scope, int maxPages) {
        this(restClient, tokenProvider, graphBaseUrl, scope, maxPages, EntraSecurityObservations.NO_OP);
    }

    /**
     * @param observations notified for each lookup, including failures before any HTTP call.
     *                     {@code null} is treated as {@link EntraSecurityObservations#NO_OP}. Cache hits in
     *                     {@link CachingGroupMembershipResolver} are not reported.
     */
    public GraphGroupMembershipResolver(RestClient restClient, EntraTokenProvider tokenProvider, URI graphBaseUrl,
            String scope, int maxPages, EntraSecurityObservations observations) {
        this.restClient = restClient;
        this.tokenProvider = tokenProvider;
        String base = graphBaseUrl.toString();
        this.baseUrl = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        this.scope = scope;
        this.maxPages = maxPages;
        this.observations = observations == null ? EntraSecurityObservations.NO_OP : observations;
    }

    @Override
    public List<GroupMembership> resolve(String tenantId, String objectId) {
        long start = System.nanoTime();
        try {
            List<GroupMembership> groups = lookup(tenantId, objectId);
            observations.graphLookup(true, Duration.ofNanos(System.nanoTime() - start));
            return groups;
        }
        catch (RuntimeException ex) {
            observations.graphLookup(false, Duration.ofNanos(System.nanoTime() - start));
            throw ex;
        }
    }

    private List<GroupMembership> lookup(String tenantId, String objectId) {
        if (objectId == null || !GUID.matcher(objectId).matches()) {
            throw new GroupResolutionException("Refusing Graph lookup for a non-GUID object id");
        }
        String next = baseUrl + "/v1.0/users/" + objectId + "/transitiveMemberOf?$select=id,displayName&$top=999";
        List<GroupMembership> groups = new ArrayList<>();
        int pages = 0;
        while (next != null) {
            if (++pages > maxPages) {
                throw new GroupResolutionException("Graph group lookup exceeded " + maxPages + " pages");
            }
            JsonNode page = fetch(next);
            for (JsonNode item : page.path("value")) {
                String type = item.path("@odata.type").asText(GROUP_TYPE);
                String id = item.path("id").asText(null);
                if (GROUP_TYPE.equals(type) && id != null) {
                    groups.add(new GroupMembership(id, item.path("displayName").asText(null)));
                }
            }
            JsonNode link = page.get("@odata.nextLink");
            next = link != null && !link.isNull() ? link.asText() : null;
        }
        return groups;
    }

    private JsonNode fetch(String url) {
        String token = tokenProvider.getToken(scope).value();
        try {
            JsonNode body = restClient.get()
                    .uri(URI.create(url))
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .body(JsonNode.class);
            if (body == null) {
                throw new GroupResolutionException("Graph returned an empty response");
            }
            return body;
        }
        catch (RestClientResponseException ex) {
            throw new GroupResolutionException("Graph group lookup failed with HTTP " + ex.getStatusCode().value(), ex);
        }
        catch (RestClientException ex) {
            throw new GroupResolutionException("Graph group lookup failed: " + ex.getMessage(), ex);
        }
    }
}
