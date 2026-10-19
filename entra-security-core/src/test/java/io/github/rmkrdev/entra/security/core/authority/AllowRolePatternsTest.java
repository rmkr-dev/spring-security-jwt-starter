package io.github.rmkrdev.entra.security.core.authority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.AuthorityUtils;

class AllowRolePatternsTest {

    @Test
    void globsMatchCaseInsensitivelyWithOrWithoutPrefix() {
        AllowRolePatterns patterns = new AllowRolePatterns(List.of("*hardware*"), false);
        assertThat(patterns.match(AuthorityUtils.createAuthorityList("ROLE_READER", "ROLE_Hardware_Admin")))
                .hasValueSatisfying(match -> {
                    assertThat(match.role()).isEqualTo("ROLE_Hardware_Admin");
                    assertThat(match.pattern()).isEqualTo("*hardware*");
                });
        assertThat(patterns.match(AuthorityUtils.createAuthorityList("ROLE_READER"))).isEmpty();
        assertThat(patterns.match(AuthorityUtils.createAuthorityList("SCOPE_hardware"))).isEmpty();
        assertThat(new AllowRolePatterns(List.of("ROLE_ADM?N"), false)
                .match(AuthorityUtils.createAuthorityList("ROLE_admin"))).isPresent();
        assertThat(new AllowRolePatterns(List.of("*hardware*"), true)
                .match(AuthorityUtils.createAuthorityList("ROLE_HARDWARE"))).isEmpty();
    }

    @Test
    void regexMustMatchTheWholeName() {
        AllowRolePatterns patterns = new AllowRolePatterns(Arrays.asList("regex:ops\\.(read|write)", " ", null),
                false);
        assertThat(patterns.match(AuthorityUtils.createAuthorityList("ROLE_OPS.WRITE"))).isPresent();
        assertThat(patterns.match(AuthorityUtils.createAuthorityList("ROLE_OPS.WRITE.ALL"))).isEmpty();
        assertThat(new AllowRolePatterns(List.of("a.b*"), false)
                .match(AuthorityUtils.createAuthorityList("ROLE_axb"))).isEmpty();
        assertThatThrownBy(() -> new AllowRolePatterns(List.of("regex:("), false))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("regex:(");
        assertThat(new AllowRolePatterns(null, false).isEmpty()).isTrue();
        assertThat(new AllowRolePatterns(null, false).match(null)).isEmpty();
    }
}
