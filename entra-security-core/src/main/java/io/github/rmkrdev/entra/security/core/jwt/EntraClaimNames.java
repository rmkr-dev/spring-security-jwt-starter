package io.github.rmkrdev.entra.security.core.jwt;

/**
 * Claim names used by Microsoft Entra ID access tokens.
 */
public final class EntraClaimNames {

    public static final String TENANT_ID = "tid";
    public static final String OBJECT_ID = "oid";
    public static final String AUTHORIZED_PARTY = "azp";
    public static final String APP_ID = "appid";
    public static final String IDENTITY_TYPE = "idtyp";
    public static final String SCOPE = "scp";
    public static final String ROLES = "roles";
    public static final String GROUPS = "groups";
    public static final String HAS_GROUPS = "hasgroups";
    public static final String CLAIM_NAMES = "_claim_names";
    public static final String VERSION = "ver";
    public static final String NAME = "name";
    public static final String PREFERRED_USERNAME = "preferred_username";
    public static final String UPN = "upn";
    public static final String UNIQUE_NAME = "unique_name";

    private EntraClaimNames() {
    }
}
