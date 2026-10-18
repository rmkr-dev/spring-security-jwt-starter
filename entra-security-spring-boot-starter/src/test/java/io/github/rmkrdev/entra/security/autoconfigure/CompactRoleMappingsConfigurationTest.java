package io.github.rmkrdev.entra.security.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import io.github.rmkrdev.entra.security.core.authority.EntraAuthorityMapper;
import io.github.rmkrdev.entra.security.core.principal.PrincipalType;

class CompactRoleMappingsConfigurationTest {

    private static final String TENANT = "entra.security.tenant-id=11111111-1111-1111-1111-111111111111";
    private static final String CLIENT = "entra.security.client-id=22222222-2222-2222-2222-222222222222";
    private static final String ADMINS = "0b5c1d7e-1111-4a4a-9b9b-000000000001";
    private static final String READERS = "0b5c1d7e-1111-4a4a-9b9b-000000000002";
    private static final String CALLER = "33333333-3333-3333-3333-333333333333";

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EntraSecurityAutoConfiguration.class,
                    EntraOutboundAutoConfiguration.class, SecurityAutoConfiguration.class,
                    UserDetailsServiceAutoConfiguration.class, OAuth2ResourceServerAutoConfiguration.class,
                    WebMvcAutoConfiguration.class, JacksonAutoConfiguration.class,
                    HttpMessageConvertersAutoConfiguration.class))
            .withPropertyValues(TENANT, CLIENT);

    @Test
    void compactMappingsFromEnvironmentVariablesReachTheAuthorityMapper() {
        Map<String, Object> env = Map.of(
                "ENTRA_SECURITY_GROUPROLEMAPPINGSCOMPACT", ADMINS + "=ADMIN," + ADMINS + "=READER;" + READERS + "=READER",
                "ENTRA_SECURITY_APPROLEMAPPINGSCOMPACT", "Orders.Read=ORDERS_READER|AUDITOR",
                "ENTRA_SECURITY_CLIENTROLEMAPPINGSCOMPACT", CALLER + "=TRUSTED_SERVICE");
        runner.withInitializer(context -> context.getEnvironment().getPropertySources().addFirst(
                new SystemEnvironmentPropertySource(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME, env)))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    EntraAuthorityMapper mapper = context.getBean(EntraAuthorityMapper.class);
                    assertThat(mapper.map(PrincipalType.USER, List.of(ADMINS), List.of(), List.of(), null))
                            .containsExactly("ROLE_ADMIN", "ROLE_READER");
                    assertThat(mapper.map(PrincipalType.USER, List.of(READERS), List.of(), List.of(), null))
                            .containsExactly("ROLE_READER");
                    assertThat(mapper.map(PrincipalType.SERVICE, List.of(), List.of("Orders.Read"), List.of(),
                            CALLER)).contains("ROLE_ORDERS_READER", "ROLE_AUDITOR", "ROLE_TRUSTED_SERVICE");
                    assertThat(mapper.isKnownClient(CALLER)).isTrue();
                });
    }

    @Test
    void compactAndMapFormsAreMerged() {
        runner.withPropertyValues("entra.security.group-role-mappings." + ADMINS + "=ADMIN",
                "entra.security.group-role-mappings-compact=" + ADMINS + "=AUDITOR;" + READERS + "=READER")
                .run(context -> {
                    EntraSecurityProperties properties = context.getBean(EntraSecurityProperties.class);
                    assertThat(properties.resolveGroupRoleMappings()).containsExactly(
                            Map.entry(ADMINS, List.of("ADMIN", "AUDITOR")), Map.entry(READERS, List.of("READER")));
                    EntraAuthorityMapper mapper = context.getBean(EntraAuthorityMapper.class);
                    assertThat(mapper.map(PrincipalType.USER, List.of(ADMINS), List.of(), List.of(), null))
                            .containsExactly("ROLE_ADMIN", "ROLE_AUDITOR");
                });
    }

    @Test
    void malformedCompactMappingFailsStartupNamingThePropertyAndEntry() {
        runner.withPropertyValues("entra.security.group-role-mappings-compact=" + ADMINS + "=ADMIN;" + READERS)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootMessage(context.getStartupFailure()))
                            .contains("groupRoleMappingsCompact")
                            .contains("entra.security.group-role-mappings-compact: entry 2 '" + READERS
                                    + "' is missing '='");
                });
    }

    @Test
    void nonGuidClientIdInCompactClientMappingFailsStartup() {
        runner.withPropertyValues("entra.security.client-role-mappings-compact=orders-api=SERVICE")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootMessage(context.getStartupFailure()))
                            .contains("entra.security.client-role-mappings-compact: entry 1 'orders-api=SERVICE' "
                                    + "has client id 'orders-api', which is not a GUID");
                });
    }

    @Test
    void everyMalformedCompactPropertyIsReported() {
        runner.withPropertyValues("entra.security.app-role-mappings-compact=Orders Read=READER",
                "entra.security.client-role-mappings-compact=" + CALLER + "=")
                .run(context -> assertThat(rootMessage(context.getStartupFailure()))
                        .contains("app-role-mappings-compact: entry 1")
                        .contains("client-role-mappings-compact: entry 1 '" + CALLER + "=' has no role after '='"));
    }

    private static String rootMessage(Throwable failure) {
        StringBuilder message = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            message.append(t.getMessage()).append('\n');
        }
        return message.toString();
    }
}
