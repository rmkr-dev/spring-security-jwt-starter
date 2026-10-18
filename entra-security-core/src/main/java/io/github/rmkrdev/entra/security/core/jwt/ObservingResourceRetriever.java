package io.github.rmkrdev.entra.security.core.jwt;

import java.io.IOException;
import java.net.URL;
import java.time.Duration;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;

import io.github.rmkrdev.entra.security.core.observe.EntraSecurityObservations;

/**
 * Counts JWKS HTTP fetches. Nimbus calls this only on a cache miss or refresh, not on cache hits.
 */
final class ObservingResourceRetriever extends DefaultResourceRetriever {

    private final EntraSecurityObservations observations;

    ObservingResourceRetriever(int connectTimeout, int readTimeout, int sizeLimit,
            EntraSecurityObservations observations) {
        super(connectTimeout, readTimeout, sizeLimit);
        this.observations = observations;
    }

    @Override
    public Resource retrieveResource(URL url) throws IOException {
        long start = System.nanoTime();
        try {
            Resource resource = super.retrieveResource(url);
            observations.jwksRefresh(true, Duration.ofNanos(System.nanoTime() - start));
            return resource;
        }
        catch (IOException | RuntimeException ex) {
            observations.jwksRefresh(false, Duration.ofNanos(System.nanoTime() - start));
            throw ex;
        }
    }
}
