package io.github.rmkrdev.entra.security.autoconfigure.keyvault;

import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.Locale;

import io.github.rmkrdev.entra.security.core.token.ClientCertificateCredential;

/**
 * Turns the secret behind a Key Vault certificate into a {@link ClientCertificateCredential}.
 * <p>
 * Key Vault keeps the private key of a certificate in a secret with the same name. Its value is a
 * base64-encoded PKCS#12 file without a password ({@code application/x-pkcs12}) or PEM text with the
 * private key and the certificate chain ({@code application/x-pem-file}), depending on the certificate
 * policy's content type.
 */
final class KeyVaultCertificates {

    static final String PKCS12 = "application/x-pkcs12";
    static final String PEM = "application/x-pem-file";

    private KeyVaultCertificates() {
    }

    static ClientCertificateCredential fromSecret(String value, String contentType, String source) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(source + " has no secret value; check that the certificate has been "
                    + "issued and its private key is exportable");
        }
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT).trim();
        boolean pem = PEM.equals(type) || (type.isEmpty() && value.stripLeading().startsWith("-----BEGIN"));
        if (pem) {
            return ClientCertificateCredential.fromPem(value);
        }
        if (!type.isEmpty() && !PKCS12.equals(type)) {
            throw new IllegalStateException(source + " has content type '" + contentType + "'; expected "
                    + PKCS12 + " or " + PEM);
        }
        byte[] pkcs12;
        try {
            pkcs12 = Base64.getMimeDecoder().decode(value.trim());
        }
        catch (IllegalArgumentException ex) {
            throw new IllegalStateException(source + " is not a base64-encoded PKCS#12 certificate", ex);
        }
        return ClientCertificateCredential.fromPkcs12(new ByteArrayInputStream(pkcs12), "");
    }
}
