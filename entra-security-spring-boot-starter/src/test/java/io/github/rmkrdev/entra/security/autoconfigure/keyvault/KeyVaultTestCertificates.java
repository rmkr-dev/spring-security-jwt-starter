package io.github.rmkrdev.entra.security.autoconfigure.keyvault;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

import io.github.rmkrdev.entra.security.core.test.TestCertificates;

/** Secret values in the shapes Key Vault returns for a certificate. */
final class KeyVaultTestCertificates {

    private KeyVaultTestCertificates() {
    }

    /** A base64-encoded PKCS#12 file without a password, as Key Vault returns for application/x-pkcs12. */
    static String pkcs12Secret(Path pkcs12) throws Exception {
        KeyStore source = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(pkcs12)) {
            source.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        PrivateKey key = (PrivateKey) source.getKey("client", TestCertificates.PASSWORD.toCharArray());
        Certificate[] chain = source.getCertificateChain("client");
        KeyStore target = KeyStore.getInstance("PKCS12");
        target.load(null, null);
        target.setKeyEntry("kv", key, new char[0], chain);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        target.store(out, new char[0]);
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    /** PEM text with the key first and then the certificate, as Key Vault returns for application/x-pem-file. */
    static String pemSecret(Path pkcs12) throws Exception {
        String pem = TestCertificates.pemText(pkcs12);
        int key = pem.indexOf("-----BEGIN PRIVATE KEY-----");
        return pem.substring(key) + pem.substring(0, key);
    }

    static X509Certificate certificate(Path pkcs12) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(pkcs12)) {
            store.load(in, TestCertificates.PASSWORD.toCharArray());
        }
        return (X509Certificate) store.getCertificate("client");
    }
}
