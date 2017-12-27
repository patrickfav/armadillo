package at.favre.lib.armadillo;

import android.support.annotation.NonNull;

import java.security.SecureRandom;

/**
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

public interface EncryptionProtocol {

    String deriveContentKey(String originalContentKey);

    byte[] encrypt(@NonNull String contentKey, byte[] rawContent) throws EncryptionProtocolException;

    byte[] encrypt(@NonNull String contentKey, char[] password, byte[] rawContent) throws EncryptionProtocolException;

    byte[] decrypt(@NonNull String contentKey, byte[] encryptedContent) throws EncryptionProtocolException;

    byte[] decrypt(@NonNull String contentKey, char[] password, byte[] encryptedContent) throws EncryptionProtocolException;

    interface Factory {
        EncryptionProtocol create(byte[] preferenceSalt);

        StringMessageDigest getStringMessageDigest();

        DataObfuscator createDataObfuscator();

        SecureRandom getSecureRandom();
    }
}
