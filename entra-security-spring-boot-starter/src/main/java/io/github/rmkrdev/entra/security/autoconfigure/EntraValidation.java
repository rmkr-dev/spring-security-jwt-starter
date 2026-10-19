package io.github.rmkrdev.entra.security.autoconfigure;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.client.RestClient;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.Introspection;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.IntrospectionType;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties.ValidationMode;
import io.github.rmkrdev.entra.security.core.introspect.CachingTokenIntrospector;
import io.github.rmkrdev.entra.security.core.introspect.HybridJwtDecoder;
import io.github.rmkrdev.entra.security.core.introspect.IntrospectedClaimsMapper;
import io.github.rmkrdev.entra.security.core.introspect.IntrospectionCircuitBreaker;
import io.github.rmkrdev.entra.security.core.introspect.IntrospectionClientAuthentication;
import io.github.rmkrdev.entra.security.core.introspect.IntrospectionJwtDecoder;
import io.github.rmkrdev.entra.security.core.introspect.Rfc7662TokenIntrospector;
import io.github.rmkrdev.entra.security.core.introspect.TokenIntrospector;
import io.github.rmkrdev.entra.security.core.introspect.UserInfoTokenIntrospector;
import io.github.rmkrdev.entra.security.core.jwt.EntraJwtDecoders;
import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;
import io.github.rmkrdev.entra.security.core.token.EntraTokenProvider;

/**
 * Builds the token decoder for {@code entra.security.validation.mode}: the JWKS decoder, the remote check, or
 * both. Shared by the servlet and reactive auto-configurations.
 */
public final class EntraValidation {

    private EntraValidation() {
    }

    /**
     * The decoder for the configured mode.
     *
     * @param introspector the remote check; required unless the mode is {@code jwks}
     */
    public static JwtDecoder decoder(EntraSecurityProperties properties, EntraEndpoints endpoints,
            JWKSource<SecurityContext> jwkSource, TokenIntrospector introspector) {
        ValidationMode mode = properties.getValidation().getMode();
        if (mode == ValidationMode.JWKS) {
            return local(properties, endpoints, jwkSource);
        }
        if (introspector == null) {
            throw new IllegalStateException("entra.security.validation.mode=" + mode.name().toLowerCase()
                    + " needs a TokenIntrospector bean");
        }
        JwtDecoder remote = new IntrospectionJwtDecoder(introspector, claimsMapper(properties),
                remoteValidator(properties, endpoints));
        if (mode == ValidationMode.INTROSPECTION) {
            return remote;
        }
        HybridJwtDecoder.Strategy strategy = properties.getValidation().getHybridStrategy()
                == EntraSecurityProperties.HybridStrategy.FALLBACK ? HybridJwtDecoder.Strategy.FALLBACK
                        : HybridJwtDecoder.Strategy.BOTH;
        return new HybridJwtDecoder(local(properties, endpoints, jwkSource), introspector, remote, strategy);
    }

    private static JwtDecoder local(EntraSecurityProperties properties, EntraEndpoints endpoints,
            JWKSource<SecurityContext> jwkSource) {
        return EntraJwtDecoders.create(jwkSource, endpoints.issuers(), properties.resolveAudiences(),
                properties.resolveRequiredTenantId(), properties.getClockSkew());
    }

    /**
     * The remote check with its cache and circuit breaker.
     *
     * @param appTokens this API's app-only token provider, used for {@code auth-method=bearer}; may be {@code null}
     *                  otherwise
     */
    public static CachingTokenIntrospector introspector(EntraSecurityProperties properties, EntraEndpoints endpoints,
            EntraTokenProvider appTokens, Clock clock, EntraSecurityObservations observations) {
        Introspection config = properties.getValidation().getIntrospection();
        RestClient restClient = restClient(config.getConnectTimeout(), config.getReadTimeout());
        URI uri = introspectionUri(properties, endpoints);
        TokenIntrospector delegate = config.getType() == IntrospectionType.USERINFO
                ? new UserInfoTokenIntrospector(restClient, uri)
                : new Rfc7662TokenIntrospector(restClient, uri, authentication(properties, appTokens),
                        config.getTokenTypeHint());
        return new CachingTokenIntrospector(delegate, config.getPositiveCacheTtl(), config.getNegativeCacheTtl(),
                config.getCacheMaxEntries(),
                new IntrospectionCircuitBreaker(config.getFailureThreshold(), config.getOpenDuration(), clock), clock,
                observations);
    }

    /** The configured endpoint, or the discovered or default one for the check type. */
    static URI introspectionUri(EntraSecurityProperties properties, EntraEndpoints endpoints) {
        Introspection config = properties.getValidation().getIntrospection();
        if (config.getUri() != null) {
            return config.getUri();
        }
        if (config.getType() == IntrospectionType.USERINFO) {
            return endpoints.userinfoEndpoint();
        }
        String discovered = endpoints.metadata("introspection_endpoint");
        if (discovered == null) {
            throw new IllegalStateException("entra.security.validation.mode=" + properties.getValidation().getMode()
                    .name().toLowerCase() + " with introspection.type=rfc7662 needs "
                    + "entra.security.validation.introspection.uri, or OIDC discovery with an introspection_endpoint. "
                    + "Microsoft Entra ID has no RFC 7662 endpoint: use mode=jwks for Entra tokens");
        }
        return URI.create(discovered);
    }

    private static IntrospectionClientAuthentication authentication(EntraSecurityProperties properties,
            EntraTokenProvider appTokens) {
        Introspection config = properties.getValidation().getIntrospection();
        switch (config.getAuthMethod()) {
            case CLIENT_SECRET_POST:
                return IntrospectionClientAuthentication.clientSecretPost(properties.resolveIntrospectionClientId(),
                        properties.resolveIntrospectionClientSecret());
            case BEARER:
                if (appTokens == null) {
                    throw new IllegalStateException("introspection.auth-method=bearer needs entra.security.credential");
                }
                String scope = config.getScope();
                return IntrospectionClientAuthentication.bearer(() -> appTokens.getToken(scope).value());
            case NONE:
                return IntrospectionClientAuthentication.none();
            case CLIENT_SECRET_BASIC:
            default:
                return IntrospectionClientAuthentication.clientSecretBasic(properties.resolveIntrospectionClientId(),
                        properties.resolveIntrospectionClientSecret());
        }
    }

    private static IntrospectedClaimsMapper claimsMapper(EntraSecurityProperties properties) {
        Introspection config = properties.getValidation().getIntrospection();
        return config.getType() == IntrospectionType.USERINFO
                ? IntrospectedClaimsMapper.userInfo(config.getClaimsMapping())
                : IntrospectedClaimsMapper.rfc7662(config.getClaimsMapping());
    }

    private static OAuth2TokenValidator<Jwt> remoteValidator(EntraSecurityProperties properties,
            EntraEndpoints endpoints) {
        Introspection config = properties.getValidation().getIntrospection();
        if (config.getType() == IntrospectionType.RFC7662 && config.isValidateClaims()) {
            return EntraJwtDecoders.validator(endpoints.issuers(), properties.resolveAudiences(),
                    properties.resolveRequiredTenantId(), properties.getClockSkew());
        }
        return timestamps(properties.getClockSkew(), Clock.systemUTC());
    }

    /** Rejects tokens whose exp has passed or whose nbf is in the future, when those claims are present. */
    static OAuth2TokenValidator<Jwt> timestamps(Duration skew, Clock clock) {
        return jwt -> {
            Instant now = clock.instant();
            if (jwt.getExpiresAt() != null && now.minus(skew).isAfter(jwt.getExpiresAt())) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Jwt expired at "
                        + jwt.getExpiresAt(), null));
            }
            if (jwt.getNotBefore() != null && now.plus(skew).isBefore(jwt.getNotBefore())) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Jwt used before "
                        + jwt.getNotBefore(), null));
            }
            return OAuth2TokenValidatorResult.success();
        };
    }

    static RestClient restClient(Duration connectTimeout, Duration readTimeout) {
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(httpClient);
        factory.setReadTimeout(readTimeout);
        return RestClient.builder().requestFactory(factory).build();
    }
}
