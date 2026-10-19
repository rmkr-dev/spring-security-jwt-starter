package io.github.rmkrdev.entra.security.support;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * A throwaway server certificate for a test host, generated with the JDK's keytool so no key material is
 * committed, and a client SSL context that trusts only that certificate.
 */
public final class TlsTestCertificates {

    public static final String PASSWORD = "changeit";

    private TlsTestCertificates() {
    }

    /** Creates a PKCS#12 keystore with a self-signed certificate whose SAN is the given DNS name. */
    public static Path serverKeystore(Path directory, String dnsName) throws Exception {
        Path keystore = directory.resolve(dnsName + ".p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process process = new ProcessBuilder(keytool, "-genkeypair", "-alias", "server", "-keyalg", "RSA",
                "-keysize", "2048", "-dname", "CN=" + dnsName, "-ext", "SAN=dns:" + dnsName, "-validity", "2",
                "-storetype", "PKCS12", "-keystore", keystore.toString(), "-storepass", PASSWORD, "-keypass",
                PASSWORD)
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: " + output);
        }
        return keystore;
    }

    /** An SSL context that trusts only the certificate in the keystore, with normal hostname checks. */
    public static SSLContext trusting(Path keystore) throws Exception {
        KeyStore source = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            source.load(in, PASSWORD.toCharArray());
        }
        Certificate certificate = source.getCertificate("server");
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("server", certificate);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, factory.getTrustManagers(), null);
        return context;
    }
}
