package io.github.rmkrdev.entra.security.core.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import io.github.rmkrdev.entra.security.core.test.TestCertificates;

class RefreshingCertificateCredentialTest {

    private static final URI ENDPOINT = URI.create("https://login.example/tenant/oauth2/v2.0/token");
    private static final Duration REFRESH = Duration.ofHours(1);
    private static final Duration RETRY = Duration.ofMinutes(1);

    @TempDir
    static Path dir;

    private static ClientCertificateCredential first;
    private static ClientCertificateCredential second;

    private MutableClock clock;
    private AtomicInteger loads;
    private Deque<Supplier<ClientCertificateCredential>> results;
    private RefreshingCertificateCredential credential;

    @BeforeAll
    static void certificates() throws Exception {
        first = ClientCertificateCredential.fromFile(TestCertificates.pkcs12(Files.createDirectory(dir.resolve("a"))),
                TestCertificates.PASSWORD);
        second = ClientCertificateCredential.fromFile(TestCertificates.pkcs12(Files.createDirectory(dir.resolve("b"))),
                TestCertificates.PASSWORD);
    }

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-10-18T10:00:00Z"));
        loads = new AtomicInteger();
        results = new ArrayDeque<>();
        credential = new RefreshingCertificateCredential("vault 'kv-test', certificate 'api'", () -> {
            loads.incrementAndGet();
            Supplier<ClientCertificateCredential> next = results.size() > 1 ? results.poll() : results.peek();
            return next.get();
        }, REFRESH, RETRY, "key_vault_certificate", clock);
    }

    @Test
    void loadsOnFirstUseAndCachesUntilTheRefreshInterval() {
        results.add(() -> first);

        assertThat(loads).hasValue(0);
        assertThat(credential.getCertificate()).isEqualTo(first.getCertificate());
        contribute();
        clock.advance(REFRESH.minusSeconds(1));
        contribute();

        assertThat(loads).hasValue(1);
        assertThat(credential.credentialType()).isEqualTo("key_vault_certificate");
    }

    @Test
    void reloadsAfterTheIntervalAndPicksUpARotatedCertificate() {
        results.add(() -> first);
        results.add(() -> second);

        assertThat(credential.getCertificate()).isEqualTo(first.getCertificate());
        clock.advance(REFRESH);

        assertThat(credential.getCertificate()).isEqualTo(second.getCertificate());
        assertThat(loads).hasValue(2);
    }

    @Test
    void failedReloadKeepsTheCachedCertificateAndRetriesLater() {
        results.add(() -> first);
        results.add(() -> {
            throw new IllegalStateException("vault unreachable");
        });
        results.add(() -> second);

        assertThat(credential.getCertificate()).isEqualTo(first.getCertificate());
        clock.advance(REFRESH);
        assertThat(credential.getCertificate()).isEqualTo(first.getCertificate());
        assertThat(loads).hasValue(2);

        clock.advance(RETRY.minusSeconds(1));
        assertThat(credential.getCertificate()).isEqualTo(first.getCertificate());
        assertThat(loads).hasValue(2);

        clock.advance(Duration.ofSeconds(1));
        assertThat(credential.getCertificate()).isEqualTo(second.getCertificate());
        assertThat(loads).hasValue(3);
    }

    @Test
    void firstLoadFailureReachesTheCallerAndIsRetriedOnTheNextRequest() {
        results.add(() -> {
            throw new IllegalStateException("403 Forbidden");
        });
        results.add(() -> first);

        assertThatThrownBy(this::contribute)
                .isInstanceOf(EntraTokenAcquisitionException.class)
                .hasMessage("Unable to load the client certificate from vault 'kv-test', certificate 'api': "
                        + "403 Forbidden");
        contribute();
        assertThat(loads).hasValue(2);
    }

    @Test
    void nullCertificateIsAnError() {
        results.add(() -> null);

        assertThatThrownBy(credential::getCertificate).isInstanceOf(EntraTokenAcquisitionException.class)
                .hasMessageContaining("No client certificate was returned");
    }

    @Test
    void refreshReloadsImmediately() {
        results.add(() -> first);
        results.add(() -> second);
        credential.getCertificate();

        credential.refresh();

        assertThat(credential.getCertificate()).isEqualTo(second.getCertificate());
    }

    @Test
    void intervalsMustBePositive() {
        assertThatThrownBy(() -> new RefreshingCertificateCredential("s", () -> first, Duration.ZERO, RETRY, "t",
                clock)).hasMessage("refreshInterval must be positive");
        assertThatThrownBy(() -> new RefreshingCertificateCredential("s", () -> first, REFRESH, null, "t", clock))
                .hasMessage("retryInterval must be positive");
    }

    @Test
    void contributesASignedAssertion() {
        results.add(() -> first);

        MultiValueMap<String, String> form = contribute();

        assertThat(form.getFirst("client_assertion_type")).isEqualTo(EntraCredential.CLIENT_ASSERTION_TYPE_JWT_BEARER);
        assertThat(form.getFirst("client_assertion")).isNotBlank();
        assertThat(credential.toString()).contains("kv-test").doesNotContain("PRIVATE");
    }

    private MultiValueMap<String, String> contribute() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        credential.contribute(form, ENDPOINT, "app-id");
        return form;
    }

    static final class MutableClock extends Clock {

        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
