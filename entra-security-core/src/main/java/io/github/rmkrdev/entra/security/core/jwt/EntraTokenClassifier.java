package io.github.rmkrdev.entra.security.core.jwt;

import org.springframework.security.oauth2.jwt.Jwt;

import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

/**
 * Decides whether a token represents a user or an application.
 * <p>
 * The optional {@code idtyp} claim ({@code user} or {@code app}) wins when present. Otherwise a token
 * with a non-empty {@code scp} claim is a delegated user token, and a token without one is app-only,
 * which is the check Microsoft documents for access tokens.
 */
public class EntraTokenClassifier {

    public PrincipalType classify(Jwt jwt) {
        String idtyp = jwt.getClaimAsString(EntraClaimNames.IDENTITY_TYPE);
        if ("app".equalsIgnoreCase(idtyp)) {
            return PrincipalType.SERVICE;
        }
        if ("user".equalsIgnoreCase(idtyp)) {
            return PrincipalType.USER;
        }
        return EntraClaims.scopes(jwt).isEmpty() ? PrincipalType.SERVICE : PrincipalType.USER;
    }
}
