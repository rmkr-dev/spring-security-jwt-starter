package io.github.rmkrdev.entra.security.core.outbound;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.net.URI;
import java.util.List;

import org.junit.jupiter.api.Test;

class OutboundTargetTest {

    @Test
    void urlPatternMatchesSchemeHostAndPath() {
        OutboundTarget target = OutboundTarget.url("https://example.text.com/api/**");
        assertThat(target.matches(URI.create("https://example.text.com/api/a"))).isTrue();
        assertThat(target.matches(URI.create("https://EXAMPLE.text.com./api/a/b?x=1"))).isTrue();
        assertThat(target.matches(URI.create("https://example.text.com:8443/api/a"))).isTrue();
        assertThat(target.matches(URI.create("https://example.text.com/other"))).isFalse();
        assertThat(target.matches(URI.create("http://example.text.com/api/a"))).isFalse();
        assertThat(target.matches(URI.create("https://evil.example.text.com/api/a"))).isFalse();
        assertThat(target.matches(URI.create("https://example.text.com.evil.test/api/a"))).isFalse();
    }

    @Test
    void urlPatternWithoutPathMatchesEverythingAndPortIsExact() {
        OutboundTarget target = OutboundTarget.url("http://*.shop.svc.cluster.local:8080");
        assertThat(target.matches(URI.create("http://orders.shop.svc.cluster.local:8080/x"))).isTrue();
        assertThat(target.matches(URI.create("http://orders.shop.svc.cluster.local:8080"))).isTrue();
        assertThat(target.matches(URI.create("http://orders.shop.svc.cluster.local/x"))).isFalse();
        assertThat(target.matches(URI.create("http://shop.svc.cluster.local:8080/x"))).isFalse();
        assertThat(OutboundTarget.url("https://api.test:443").matches(URI.create("https://api.test/"))).isTrue();
        assertThat(OutboundTarget.url("http://api.test:80").matches(URI.create("http://api.test/"))).isTrue();
    }

    @Test
    void hostPatternsUseHttpsAndHttpOnlyInsideTheCluster() {
        OutboundTarget cluster = OutboundTarget.host("*.svc.cluster.local", null, List.of());
        assertThat(cluster.matches(URI.create("http://orders.shop.svc.cluster.local/a"))).isTrue();
        assertThat(cluster.matches(URI.create("https://orders.shop.svc.cluster.local/a"))).isTrue();

        OutboundTarget external = OutboundTarget.host("partner.example.test", null, List.of("/v1/**"));
        assertThat(external.matches(URI.create("https://partner.example.test/v1/x"))).isTrue();
        assertThat(external.matches(URI.create("https://partner.example.test/v2/x"))).isFalse();
        assertThat(external.matches(URI.create("http://partner.example.test/v1/x"))).isFalse();
        assertThat(external.matches(URI.create("ftp://partner.example.test/v1/x"))).isFalse();

        assertThat(OutboundTarget.host("partner.example.test", true, List.of())
                .matches(URI.create("http://partner.example.test/"))).isTrue();
        assertThat(OutboundTarget.host("orders.svc", false, List.of())
                .matches(URI.create("http://orders.svc/"))).isFalse();
        assertThat(OutboundTarget.host("localhost:9000", null, List.of())
                .matches(URI.create("http://localhost:9000/"))).isTrue();
        assertThat(OutboundTarget.host("*", null, List.of()).matches(URI.create("https://any.test/"))).isTrue();
        assertThat(OutboundTarget.host("*", null, List.of()).matches(URI.create("http://any.test/"))).isFalse();
    }

    @Test
    void ignoresUrisWithoutHost() {
        OutboundTarget target = OutboundTarget.host("*", null, List.of());
        assertThat(target.matches(URI.create("/relative"))).isFalse();
        assertThat(target.matches(null)).isFalse();
        assertThat(target.matchesHost(URI.create("/relative"))).isFalse();
        assertThat(OutboundTarget.isInternal("[::1]")).isTrue();
        assertThat(target.toString()).contains("*");
    }

    @Test
    void rejectsInvalidPatterns() {
        assertThatIllegalArgumentException().isThrownBy(() -> OutboundTarget.url("example.text.com/api"));
        assertThatIllegalArgumentException().isThrownBy(() -> OutboundTarget.url("ftp://example.text.com"));
        assertThatIllegalArgumentException().isThrownBy(() -> OutboundTarget.url("https://example.text.com/a?b"));
        assertThatIllegalArgumentException().isThrownBy(() -> OutboundTarget.url("https://ex*ample.com/"));
        assertThatIllegalArgumentException().isThrownBy(() -> OutboundTarget.url("https://example.com:x/"));
        assertThatIllegalArgumentException().isThrownBy(() -> OutboundTarget.url("https://example.com:70000/"));
        assertThatIllegalArgumentException().isThrownBy(() -> OutboundTarget.url("https://user@example.com/"));
        assertThatIllegalArgumentException().isThrownBy(() -> OutboundTarget.host("*.*", null, List.of()));
        assertThatIllegalArgumentException().isThrownBy(() -> OutboundTarget.host("", null, List.of()));
        assertThatIllegalArgumentException().isThrownBy(() -> OutboundTarget.host("a.test", null, List.of("api")));
    }
}
