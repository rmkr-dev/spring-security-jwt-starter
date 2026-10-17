package io.github.rmkrdev.entra.security.core.principal;

/**
 * The kind of caller behind an Entra access token.
 */
public enum PrincipalType {

    /** A signed-in user (delegated token, carries {@code scp}). */
    USER,

    /** An application calling with its own identity (client credentials, app-only token). */
    SERVICE
}
