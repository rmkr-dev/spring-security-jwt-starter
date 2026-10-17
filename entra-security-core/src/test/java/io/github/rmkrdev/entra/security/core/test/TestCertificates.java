package io.github.rmkrdev.entra.security.core.test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * Generates a throwaway self-signed client certificate with the JDK's keytool, so no key material is
 * committed to the repository.
 */
public final class TestCertificates {

    public static final String PASSWORD = "changeit";

    private TestCertificates() {
    }

    /** Creates {@code client.p12} in the directory and returns its path. */
    public static Path pkcs12(Path directory) throws IOException, InterruptedException {
        Path keystore = directory.resolve("client.p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process process = new ProcessBuilder(keytool, "-genkeypair", "-alias", "client", "-keyalg", "RSA",
                "-keysize", "2048", "-dname", "CN=entra-security-test", "-validity", "2", "-storetype", "PKCS12",
                "-keystore", keystore.toString(), "-storepass", PASSWORD, "-keypass", PASSWORD)
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: " + output);
        }
        return keystore;
    }

    /** Converts a PKCS#12 keystore to a PEM file (certificate + PKCS#8 key). */
    public static Path pem(Path pkcs12, Path target) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(pkcs12)) {
            store.load(in, PASSWORD.toCharArray());
        }
        PrivateKey key = (PrivateKey) store.getKey("client", PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate) store.getCertificate("client");
        Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII));
        String pem = "-----BEGIN CERTIFICATE-----\n" + encoder.encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n"
                + encoder.encodeToString(key.getEncoded()) + "\n-----END PRIVATE KEY-----\n";
        Files.writeString(target, pem, StandardCharsets.US_ASCII);
        return target;
    }
}
