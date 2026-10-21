package io.github.rmkrdev.entra.security.core.graph;

import java.util.List;
import java.util.regex.Pattern;

import tools.jackson.databind.JsonNode;

/**
 * Request and response handling for {@code transitiveMemberOf}, shared by the blocking and reactive Graph
 * resolvers.
 */
final class GraphPages {

    private static final Pattern GUID = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final String GROUP_TYPE = "#microsoft.graph.group";

    private GraphPages() {
    }

    static String normalizeBaseUrl(String base) {
        return base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
    }

    /**
     * The first page URL.
     *
     * @throws GroupResolutionException for an object id that is not a GUID
     */
    static String firstPage(String baseUrl, String objectId) {
        if (objectId == null || !GUID.matcher(objectId).matches()) {
            throw new GroupResolutionException("Refusing Graph lookup for a non-GUID object id");
        }
        return baseUrl + "/v1.0/users/" + objectId + "/transitiveMemberOf?$select=id,displayName&$top=999";
    }

    static GroupResolutionException tooManyPages(int maxPages) {
        return new GroupResolutionException("Graph group lookup exceeded " + maxPages + " pages");
    }

    /**
     * Adds the groups of {@code page} (directory roles and other objects are skipped) and returns the next
     * page URL, or {@code null}.
     */
    static String collect(JsonNode page, List<GroupMembership> groups) {
        for (JsonNode item : page.path("value")) {
            String type = item.path("@odata.type").asString(GROUP_TYPE);
            String id = item.path("id").asString(null);
            if (GROUP_TYPE.equals(type) && id != null) {
                groups.add(new GroupMembership(id, item.path("displayName").asString(null)));
            }
        }
        JsonNode link = page.get("@odata.nextLink");
        return link != null && !link.isNull() ? link.asString() : null;
    }
}
