package io.github.rmkrdev.entra.security.core.token;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.MultiValueMap;

/**
 * A certificate credential whose certificate is loaded from somewhere that can change, such as Azure Key
 * Vault, cached, and reloaded periodically so a rotated certificate is picked up without a restart.
 * <p>
 * The certificate is loaded on the first token request. After that it is reloaded once
 * {@code refreshInterval} has passed. A reload runs on one thread while other threads keep signing with the
 * cached certificate, and a failed reload keeps the cached certificate and is retried after
 * {@code retryInterval}. Only a failure to load the first certificate reaches the caller.
 */
public final class RefreshingCertificateCredential implements EntraCredential {

    private static final Logger log = LoggerFactory.getLogger(RefreshingCertificateCredential.class);

    private final String source;
    private final Supplier<ClientCertificateCredential> loader;
    private final Duration refreshInterval;
    private final Duration retryInterval;
    private final String credentialType;
    private final Clock clock;
    private final ReentrantLock lock = new ReentrantLock();

    private volatile Loaded loaded;

    /**
     * @param source          where the certificate comes from, for log and error messages (no secrets)
     * @param loader          loads the current certificate; called on first use and on every refresh
     * @param refreshInterval how long a loaded certificate is used before it is reloaded
     * @param retryInterval   how long to wait after a failed reload before trying again
     * @param credentialType  bounded metrics label, for example {@code key_vault_certificate}
     * @param clock           the clock
     */
    public RefreshingCertificateCredential(String source, Supplier<ClientCertificateCredential> loader,
            Duration refreshInterval, Duration retryInterval, String credentialType, Clock clock) {
        this.source = Objects.requireNonNull(source, "source");
        this.loader = Objects.requireNonNull(loader, "loader");
        this.refreshInterval = positive(refreshInterval, "refreshInterval");
        this.retryInterval = positive(retryInterval, "retryInterval");
        this.credentialType = Objects.requireNonNull(credentialType, "credentialType");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public void contribute(MultiValueMap<String, String> form, URI tokenEndpoint, String clientId) {
        current().contribute(form, tokenEndpoint, clientId);
    }

    @Override
    public String credentialType() {
        return credentialType;
    }

    /** The certificate in use, loading it first if needed. */
    public X509Certificate getCertificate() {
        return current().getCertificate();
    }

    /** Reloads the certificate now. A failure keeps the cached certificate and is rethrown. */
    public void refresh() {
        lock.lock();
        try {
            loaded = load(clock.instant());
        }
        finally {
            lock.unlock();
        }
    }

    ClientCertificateCredential current() {
        Loaded state = loaded;
        if (state == null) {
            lock.lock();
            try {
                state = loaded;
                if (state == null) {
                    state = load(clock.instant());
                    loaded = state;
                }
            }
            finally {
                lock.unlock();
            }
            return state.credential();
        }
        Instant now = clock.instant();
        if (!now.isBefore(state.nextRefresh()) && lock.tryLock()) {
            try {
                state = reloadIfDue(now);
            }
            finally {
                lock.unlock();
            }
        }
        return state.credential();
    }

    private Loaded reloadIfDue(Instant now) {
        Loaded state = loaded;
        if (now.isBefore(state.nextRefresh())) {
            return state;
        }
        try {
            Loaded fresh = load(now);
            if (!fresh.credential().getCertificate().equals(state.credential().getCertificate())) {
                log.info("Loaded a new client certificate from {} ({})", source, describe(fresh.credential()));
            }
            loaded = fresh;
            return fresh;
        }
        catch (RuntimeException ex) {
            log.warn("Unable to reload the client certificate from {}; keeping the current one ({}) and retrying "
                    + "in {}: {}", source, describe(state.credential()), retryInterval, ex.getMessage());
            Loaded retry = new Loaded(state.credential(), now.plus(retryInterval));
            loaded = retry;
            return retry;
        }
    }

    private Loaded load(Instant now) {
        ClientCertificateCredential credential;
        try {
            credential = loader.get();
        }
        catch (RuntimeException ex) {
            throw new EntraTokenAcquisitionException("Unable to load the client certificate from " + source + ": "
                    + ex.getMessage(), null, ex);
        }
        if (credential == null) {
            throw new EntraTokenAcquisitionException("No client certificate was returned by " + source, null, null);
        }
        return new Loaded(credential, now.plus(refreshInterval));
    }

    private static String describe(ClientCertificateCredential credential) {
        X509Certificate certificate = credential.getCertificate();
        return "subject=" + certificate.getSubjectX500Principal().getName() + ", expires="
                + certificate.getNotAfter().toInstant();
    }

    private static Duration positive(Duration value, String name) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return value;
    }

    @Override
    public String toString() {
        return "RefreshingCertificateCredential[source=" + source + "]";
    }

    private record Loaded(ClientCertificateCredential credential, Instant nextRefresh) {
    }
}
