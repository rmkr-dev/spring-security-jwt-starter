package io.github.rmkrdev.entra.security.core.introspect;

/**
 * Asks a remote authority whether a token is active, for example through an RFC 7662 introspection endpoint or
 * a userinfo endpoint.
 */
@FunctionalInterface
public interface TokenIntrospector {

    /**
     * Checks the token.
     *
     * @return the result; an unknown, expired or revoked token is {@link IntrospectionResult#inactive()}
     * @throws IntrospectionException when the authority could not give a definite answer (timeout, connection
     *                                failure, 5xx, rejected client credentials or an unreadable response)
     */
    IntrospectionResult introspect(String token);
}
