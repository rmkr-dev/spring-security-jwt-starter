package io.github.rmkrdev.entra.security.core.token;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.springframework.util.MultiValueMap;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Authenticates with a certificate by sending a signed client assertion (RS256, {@code x5t} header).
 * <p>
 * Load it from a PEM file holding the certificate and a PKCS#8 private key, which may be encrypted
 * ({@code ENCRYPTED PRIVATE KEY}, with a password), or from a PKCS#12 ({@code .p12}/{@code .pfx})
 * keystore.
 */
public final class ClientCertificateCredential implements EntraCredential {

    private static final Pattern PEM_BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\\s]+)-----END \\1-----");
    private static final Duration ASSERTION_LIFETIME = Duration.ofMinutes(10);

    private final PrivateKey privateKey;
    private final X509Certificate certificate;
    private final Clock clock;

    public ClientCertificateCredential(PrivateKey privateKey, X509Certificate certificate, Clock clock) {
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException("Only RSA private keys are supported for client assertions");
        }
        if (certificate == null) {
            throw new IllegalArgumentException("certificate must not be null");
        }
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.clock = clock;
    }

    /**
     * Loads a credential from a PEM or PKCS#12 file, chosen by the file extension.
     *
     * @param path     the file
     * @param password the PKCS#12 keystore password, or the password of an encrypted PEM private key;
     *                 may be {@code null}
     */
    public static ClientCertificateCredential fromFile(Path path, String password) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        try {
            if (name.endsWith(".p12") || name.endsWith(".pfx")) {
                try (InputStream in = Files.newInputStream(path)) {
                    return fromPkcs12(in, password);
                }
            }
            return fromPem(Files.readString(path, StandardCharsets.US_ASCII), password);
        }
        catch (IOException ex) {
            throw new UncheckedIOException("Unable to read client certificate " + path, ex);
        }
    }

    /**
     * Parses a PEM document containing a {@code CERTIFICATE} and an unencrypted {@code PRIVATE KEY} block.
     */
    public static ClientCertificateCredential fromPem(String pem) {
        return fromPem(pem, null);
    }

    /**
     * Parses a PEM document containing a {@code CERTIFICATE} block and a PKCS#8 private key, either
     * unencrypted ({@code PRIVATE KEY}) or encrypted ({@code ENCRYPTED PRIVATE KEY}).
     * <p>
     * Encrypted keys use PBES2 (what {@code openssl pkcs8 -topk8} and {@code openssl genpkey -aes256}
     * write, for example PBKDF2 with HMAC-SHA256 and AES-256-CBC) or a PBES1 scheme the JDK supports.
     *
     * @param pem      the PEM text
     * @param password the password of an encrypted private key; ignored for an unencrypted one
     */
    public static ClientCertificateCredential fromPem(String pem, String password) {
        X509Certificate certificate = null;
        PrivateKey key = null;
        Matcher matcher = PEM_BLOCK.matcher(pem);
        try {
            while (matcher.find()) {
                String type = matcher.group(1);
                byte[] der = Base64.getMimeDecoder().decode(matcher.group(2));
                switch (type) {
                    case "CERTIFICATE" -> {
                        if (certificate == null) {
                            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                                    .generateCertificate(new ByteArrayInputStream(der));
                        }
                    }
                    case "PRIVATE KEY" -> key = KeyFactory.getInstance("RSA")
                            .generatePrivate(new PKCS8EncodedKeySpec(der));
                    case "RSA PRIVATE KEY" -> throw new IllegalArgumentException(
                            "PKCS#1 'RSA PRIVATE KEY' PEM is not supported; convert it with "
                                    + "'openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem'");
                    case "ENCRYPTED PRIVATE KEY" -> key = KeyFactory.getInstance("RSA")
                            .generatePrivate(decrypt(der, password));
                    default -> {
                        // ignore other blocks
                    }
                }
            }
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Invalid client certificate PEM: " + ex.getMessage(), ex);
        }
        if (certificate == null || key == null) {
            throw new IllegalArgumentException(
                    "Client certificate PEM must contain a CERTIFICATE block and a PRIVATE KEY block");
        }
        return new ClientCertificateCredential(key, certificate, Clock.systemUTC());
    }

    private static PKCS8EncodedKeySpec decrypt(byte[] der, String password) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("The PEM private key is encrypted (ENCRYPTED PRIVATE KEY) but no "
                    + "password is configured; set the certificate password");
        }
        EncryptedPrivateKeyInfo info;
        try {
            info = new EncryptedPrivateKeyInfo(der);
        }
        catch (IOException ex) {
            throw new IllegalArgumentException("Invalid ENCRYPTED PRIVATE KEY block: " + ex.getMessage(), ex);
        }
        AlgorithmParameters parameters = info.getAlgParameters();
        // For PBES2 the JDK reports "PBES2"; the parameters name the full scheme, e.g. PBEWithHmacSHA256AndAES_256.
        String algorithm = parameters != null && isPbes2(info.getAlgName()) ? parameters.toString()
                : info.getAlgName();
        char[] secret = password.toCharArray();
        PBEKeySpec keySpec = new PBEKeySpec(secret);
        try {
            SecretKey key = SecretKeyFactory.getInstance(algorithm).generateSecret(keySpec);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, key, parameters);
            return info.getKeySpec(cipher);
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalArgumentException("The PEM private key is encrypted with " + algorithm
                    + ", which this JVM does not support; re-encrypt it with "
                    + "'openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256'", ex);
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Unable to decrypt the PEM private key; check the certificate "
                    + "password", ex);
        }
        finally {
            keySpec.clearPassword();
            Arrays.fill(secret, '\0');
        }
    }

    private static boolean isPbes2(String algorithm) {
        return "PBES2".equalsIgnoreCase(algorithm) || "1.2.840.113549.1.5.13".equals(algorithm);
    }

    /**
     * Loads the first private key entry of a PKCS#12 keystore.
     */
    public static ClientCertificateCredential fromPkcs12(InputStream in, String password) {
        char[] secret = password == null ? new char[0] : password.toCharArray();
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(in, secret);
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (store.isKeyEntry(alias)) {
                    PrivateKey key = (PrivateKey) store.getKey(alias, secret);
                    X509Certificate cert = (X509Certificate) store.getCertificate(alias);
                    return new ClientCertificateCredential(key, cert, Clock.systemUTC());
                }
            }
            throw new IllegalArgumentException("PKCS#12 keystore contains no private key entry");
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Unable to load PKCS#12 keystore: " + ex.getMessage(), ex);
        }
        catch (IOException ex) {
            throw new UncheckedIOException("Unable to load PKCS#12 keystore (wrong password?)", ex);
        }
    }

    @Override
    public void contribute(MultiValueMap<String, String> form, URI tokenEndpoint, String clientId) {
        form.add("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER);
        form.add("client_assertion", createAssertion(tokenEndpoint, clientId));
    }

    @Override
    public String credentialType() {
        return "certificate";
    }

    /**
     * Creates the signed client assertion JWT.
     */
    @SuppressWarnings("deprecation")
    public String createAssertion(URI tokenEndpoint, String clientId) {
        try {
            byte[] der = certificate.getEncoded();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .x509CertThumbprint(Base64URL.encode(MessageDigest.getInstance("SHA-1").digest(der)))
                    .x509CertSHA256Thumbprint(Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(der)))
                    .build();
            Instant now = clock.instant();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .audience(tokenEndpoint.toString())
                    .issuer(clientId)
                    .subject(clientId)
                    .jwtID(UUID.randomUUID().toString())
                    .notBeforeTime(Date.from(now))
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(ASSERTION_LIFETIME)))
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(privateKey));
            return jwt.serialize();
        }
        catch (GeneralSecurityException | JOSEException ex) {
            throw new IllegalStateException("Unable to create client assertion: " + ex.getMessage(), ex);
        }
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    @Override
    public String toString() {
        return "ClientCertificateCredential[subject=" + certificate.getSubjectX500Principal().getName() + "]";
    }
}
