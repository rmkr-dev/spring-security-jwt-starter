package io.github.rmkrdev.entra.security.test;

import java.lang.annotation.Annotation;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.util.ClassUtils;

import io.github.rmkrdev.entra.security.core.jwt.EntraJwtAuthenticationConverter;
import io.github.rmkrdev.entra.security.core.jwt.ReactiveEntraJwtAuthenticationConverter;
import io.github.rmkrdev.entra.security.core.principal.EntraAuthenticationToken;
import io.github.rmkrdev.entra.security.core.principal.EntraPrincipal;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

/**
 * Shared logic of the {@link WithMockEntraUser} and {@link WithMockEntraService} security context factories.
 *
 * @param <A> the annotation
 */
abstract class AbstractMockEntraSecurityContextFactory<A extends Annotation> implements WithSecurityContextFactory<A> {

    static final String DEFAULT_TENANT_ID = "00000000-0000-4000-8000-000000000000";

    private static final boolean REACTOR_PRESENT = ClassUtils.isPresent("reactor.core.publisher.Mono",
            AbstractMockEntraSecurityContextFactory.class.getClassLoader());

    private Converter<Jwt, AbstractAuthenticationToken> converter;
    private Environment environment;
    private BeanFactory beanFactory;

    @Autowired(required = false)
    public void setConverter(EntraJwtAuthenticationConverter converter) {
        this.converter = converter;
    }

    @Autowired(required = false)
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Autowired(required = false)
    public void setBeanFactory(BeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }

    @Override
    public SecurityContext createSecurityContext(A annotation) {
        EntraAuthenticationToken authentication = authenticate(toJwt(annotation), extraRoles(annotation));
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        return context;
    }

    abstract Jwt toJwt(A annotation);

    abstract List<String> extraRoles(A annotation);

    Jwt userJwt(WithMockEntraUser user) {
        Map<String, Object> claims = baseClaims(tenant(user.tenantId()), user.objectId(), user.appId());
        claims.put("sub", "user-" + user.objectId());
        claims.put("idtyp", "user");
        putList(claims, "groups", user.groups());
        putList(claims, "roles", user.appRoles());
        if (user.scopes().length > 0) {
            claims.put("scp", String.join(" ", user.scopes()));
        }
        putText(claims, "name", user.name());
        putText(claims, "preferred_username", user.username());
        return jwt(claims);
    }

    Jwt serviceJwt(WithMockEntraService service) {
        Map<String, Object> claims = baseClaims(tenant(service.tenantId()), service.objectId(), service.appId());
        claims.put("sub", service.objectId());
        claims.put("idtyp", "app");
        putList(claims, "roles", service.appRoles());
        return jwt(claims);
    }

    private EntraAuthenticationToken authenticate(Jwt jwt, List<String> extraRoles) {
        EntraAuthenticationToken mapped = map(jwt);
        if (extraRoles.isEmpty()) {
            return mapped;
        }
        EntraPrincipal p = mapped.getEntraPrincipal();
        Set<String> roles = new LinkedHashSet<>(p.roles());
        extraRoles.forEach(role -> roles.add(role.startsWith("ROLE_") ? role : "ROLE_" + role));
        EntraPrincipal principal = new EntraPrincipal(p.type(), p.tenantId(), p.objectId(), p.subject(), p.appId(),
                p.displayName(), p.username(), roles, p.appRoles(), p.groups(), p.scopes(), p.tokenVersion());
        return new EntraAuthenticationToken(jwt, principal, authorities(roles));
    }

    /**
     * Runs the starter's converter: the servlet one, or in a WebFlux application the reactive one. Without the
     * starter, roles come straight from the annotation.
     */
    private EntraAuthenticationToken map(Jwt jwt) {
        if (converter != null) {
            return converter.convert(jwt) instanceof EntraAuthenticationToken token ? token : direct(jwt);
        }
        if (REACTOR_PRESENT && beanFactory != null) {
            EntraAuthenticationToken token = ReactiveConversion.convert(beanFactory, jwt);
            if (token != null) {
                return token;
            }
        }
        return direct(jwt);
    }

    private static EntraAuthenticationToken direct(Jwt jwt) {
        PrincipalType type = "app".equals(jwt.getClaimAsString("idtyp")) ? PrincipalType.SERVICE : PrincipalType.USER;
        Set<String> appRoles = set(jwt.getClaimAsStringList("roles"));
        Set<String> roles = new LinkedHashSet<>();
        appRoles.forEach(role -> roles.add("ROLE_" + role));
        String scp = jwt.getClaimAsString("scp");
        Set<String> scopes = scp == null ? Set.of() : new LinkedHashSet<>(Arrays.asList(scp.split(" ")));
        EntraPrincipal principal = new EntraPrincipal(type, jwt.getClaimAsString("tid"), jwt.getClaimAsString("oid"),
                jwt.getSubject(), jwt.getClaimAsString("azp"), jwt.getClaimAsString("name"),
                jwt.getClaimAsString("preferred_username"), roles, appRoles, set(jwt.getClaimAsStringList("groups")),
                scopes, jwt.getClaimAsString("ver"));
        return new EntraAuthenticationToken(jwt, principal, authorities(roles));
    }

    private String tenant(String explicit) {
        if (!explicit.isEmpty()) {
            return explicit;
        }
        String configured = environment != null ? environment.getProperty("entra.security.tenant-id") : null;
        return configured != null && !configured.isBlank() ? configured : DEFAULT_TENANT_ID;
    }

    private String audience() {
        if (environment == null) {
            return "api://test";
        }
        String audience = environment.getProperty("entra.security.audiences[0]",
                environment.getProperty("entra.security.client-id"));
        return audience != null ? audience : "api://test";
    }

    private Map<String, Object> baseClaims(String tenantId, String objectId, String appId) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", "https://login.microsoftonline.com/" + tenantId + "/v2.0");
        claims.put("aud", List.of(audience()));
        claims.put("tid", tenantId);
        claims.put("oid", objectId);
        claims.put("azp", appId);
        claims.put("ver", "2.0");
        return claims;
    }

    private static Jwt jwt(Map<String, Object> claims) {
        Instant now = Instant.now();
        return Jwt.withTokenValue("mock-entra-token")
                .header("alg", "RS256")
                .header("typ", "JWT")
                .claims(c -> c.putAll(claims))
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(Duration.ofHours(1)))
                .build();
    }

    private static void putList(Map<String, Object> claims, String name, String[] values) {
        if (values.length > 0) {
            claims.put(name, List.of(values));
        }
    }

    private static void putText(Map<String, Object> claims, String name, String value) {
        if (value != null && !value.isEmpty()) {
            claims.put(name, value);
        }
    }

    private static Set<String> set(List<String> values) {
        return values == null ? Set.of() : new LinkedHashSet<>(values);
    }

    private static List<GrantedAuthority> authorities(Set<String> roles) {
        return roles.stream().<GrantedAuthority>map(SimpleGrantedAuthority::new).toList();
    }

    /**
     * Kept in its own class so Reactor is only loaded when it is on the classpath.
     */
    private static final class ReactiveConversion {

        static EntraAuthenticationToken convert(BeanFactory beanFactory, Jwt jwt) {
            ReactiveEntraJwtAuthenticationConverter converter = beanFactory
                    .getBeanProvider(ReactiveEntraJwtAuthenticationConverter.class).getIfAvailable();
            if (converter == null) {
                return null;
            }
            return converter.convert(jwt).block() instanceof EntraAuthenticationToken token ? token : null;
        }
    }
}
