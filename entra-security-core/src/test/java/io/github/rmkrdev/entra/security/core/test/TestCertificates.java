package io.github.rmkrdev.entra.security.core.test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Generates a throwaway self-signed client certificate with the JDK's keytool, so no key material is
 * committed to the repository.
 */
public final class TestCertificates {

    public static final String PASSWORD = "changeit";

    /** OID 1.2.840.113549.1.5.13 (PBES2), DER encoded. */
    private static final byte[] PBES2_OID = { 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d,
            0x01, 0x05, 0x0d };
    /** OID 1.2.840.113549.1.12.1.3 (pbeWithSHAAnd3-KeyTripleDES-CBC), DER encoded. */
    private static final byte[] PBE_SHA1_DESEDE_OID = { 0x06, 0x0a, 0x2a, (byte) 0x86, 0x48, (byte) 0x86,
            (byte) 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03 };

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

    /** The PEM text of a keystore's certificate and unencrypted PKCS#8 key. */
    public static String pemText(Path pkcs12) throws Exception {
        Path target = Files.createTempFile(pkcs12.getParent(), "client", ".pem");
        try {
            return Files.readString(pem(pkcs12, target), StandardCharsets.US_ASCII);
        }
        finally {
            Files.deleteIfExists(target);
        }
    }

    /**
     * Converts a PKCS#12 keystore to a PEM file with the certificate and an {@code ENCRYPTED PRIVATE KEY}.
     *
     * @param algorithm a JDK PBE algorithm: {@code PBEWithHmacSHA256AndAES_256} gives PBES2 (what OpenSSL
     *                  writes by default), {@code PBEWithSHA1AndDESede} a legacy PBES1 scheme
     */
    public static Path encryptedPem(Path pkcs12, Path target, String keyPassword, String algorithm) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(pkcs12)) {
            store.load(in, PASSWORD.toCharArray());
        }
        PrivateKey key = (PrivateKey) store.getKey("client", PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate) store.getCertificate("client");
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        PBEParameterSpec spec;
        if (algorithm.contains("AES")) {
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            spec = new PBEParameterSpec(salt, 10_000, new IvParameterSpec(iv));
        }
        else {
            spec = new PBEParameterSpec(salt, 2048);
        }
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE,
                SecretKeyFactory.getInstance(algorithm).generateSecret(new PBEKeySpec(keyPassword.toCharArray())),
                spec);
        byte[] encrypted = cipher.doFinal(key.getEncoded());
        AlgorithmParameters parameters = cipher.getParameters();
        // EncryptedPrivateKeyInfo cannot encode PBES2 itself, so build the DER structure directly:
        // SEQUENCE { SEQUENCE { OID, parameters }, OCTET STRING encrypted }
        byte[] oid = algorithm.contains("AES") ? PBES2_OID : PBE_SHA1_DESEDE_OID;
        byte[] identifier = der(0x30, concat(oid, parameters.getEncoded()));
        byte[] der = der(0x30, concat(identifier, der(0x04, encrypted)));
        new EncryptedPrivateKeyInfo(der); // sanity check
        Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII));
        String pem = "-----BEGIN CERTIFICATE-----\n" + encoder.encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                + encoder.encodeToString(der) + "\n-----END ENCRYPTED PRIVATE KEY-----\n";
        Files.writeString(target, pem, StandardCharsets.US_ASCII);
        return target;
    }

    private static byte[] der(int tag, byte[] content) {
        int length = content.length;
        byte[] header;
        if (length < 0x80) {
            header = new byte[] { (byte) tag, (byte) length };
        }
        else if (length < 0x100) {
            header = new byte[] { (byte) tag, (byte) 0x81, (byte) length };
        }
        else {
            header = new byte[] { (byte) tag, (byte) 0x82, (byte) (length >> 8), (byte) length };
        }
        return concat(header, content);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
