package io.github.rmkrdev.entra.security.core.principal;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

/**
 * Authentication created from a validated Entra JWT. Its principal is an {@link EntraPrincipal};
 * the raw {@link Jwt} stays available through {@link #getToken()}.
 */
public class EntraAuthenticationToken extends AbstractOAuth2TokenAuthenticationToken<Jwt> {

    private static final long serialVersionUID = 1L;

    private final EntraPrincipal entraPrincipal;

    @SuppressWarnings("this-escape") // setAuthenticated is defined on the superclass
    public EntraAuthenticationToken(Jwt jwt, EntraPrincipal principal,
            Collection<? extends GrantedAuthority> authorities) {
        super(jwt, principal, jwt, authorities);
        this.entraPrincipal = principal;
        setAuthenticated(true);
    }

    public EntraPrincipal getEntraPrincipal() {
        return entraPrincipal;
    }

    @Override
    public Map<String, Object> getTokenAttributes() {
        return getToken().getClaims();
    }

    @Override
    public String getName() {
        return entraPrincipal.getName();
    }
}
