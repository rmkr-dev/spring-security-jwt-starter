package io.github.rmkrdev.entra.security.core.cache;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** Cache keys for bearer tokens: a SHA-256 hash, so raw tokens are never held as keys. */
public final class TokenKeys {

    private static final ThreadLocal<MessageDigest> SHA256 = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    });

    private TokenKeys() {
    }

    /** The URL-safe base64 SHA-256 of the token. */
    public static String of(String token) {
        MessageDigest digest = SHA256.get();
        digest.reset();
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(digest.digest(token.getBytes(StandardCharsets.US_ASCII)));
    }
}
