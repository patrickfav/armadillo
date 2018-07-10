package at.favre.lib.armadillo;

import android.support.annotation.NonNull;

import java.security.SecureRandom;

/**
 * The definition of the whole encryption protocol. The protocol handles and orchestrates how keys
 * are derived, when to encrypt and when to obfuscate, what to do on errors.
 * <p>
 * This is more or less an internal interface, not indented to be changed by the user of this lib.
 *
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

interface EncryptionProtocol {

    /**
     * Given a original content key provided by the user creates a message digest of this key
     * with witch the original key cannot be recovered other than brute force.
     *
     * @param originalContentKey to create the digest for
     * @return the digest (hash)
     */
    String deriveContentKey(String originalContentKey);

    /**
     * Encrypts, obfuscates and optionally compresses given rawContent.
     * The given contentKey will be used to derive the encryption key.
     *
     * @param contentKey key from {@link #deriveContentKey(String)} also used to derive the encryption key
     * @param rawContent to encrypt
     * @return encrypted data
     * @throws EncryptionProtocolException when encryption was not possible
     */
    byte[] encrypt(@NonNull String contentKey, byte[] rawContent) throws EncryptionProtocolException;

    /**
     * Encrypts, obfuscates and optionally compresses given rawContent. This mode additionally uses
     * a user provided password which will be stretched by given {@link KeyStretchingFunction}.
     * The given contentKey will be used to derive the encryption key.
     *
     * @param contentKey key from {@link #deriveContentKey(String)} also used to derive the encryption key
     * @param password   provided by user
     * @param rawContent to encrypt
     * @return encrypted data
     * @throws EncryptionProtocolException when encryption was not possible
     */
    byte[] encrypt(@NonNull String contentKey, char[] password, byte[] rawContent) throws EncryptionProtocolException;

    /**
     * Decrypts, de-obfuscates and optionally de-compresses given content.
     *
     * @param contentKey       key from {@link #deriveContentKey(String)} also used to derive the encryption key
     * @param encryptedContent to decrypt etc.
     * @return original data
     * @throws EncryptionProtocolException when encryption was not possible
     */
    byte[] decrypt(@NonNull String contentKey, byte[] encryptedContent) throws EncryptionProtocolException;

    /**
     * Decrypts, de-obfuscates and optionally de-compresses given content. This mode additionally uses
     * a user provided password which will be stretched by given {@link KeyStretchingFunction}.
     *
     * @param contentKey       key from {@link #deriveContentKey(String)} also used to derive the encryption key
     * @param password         provided by user
     * @param encryptedContent to decrypt etc.
     * @return original data
     * @throws EncryptionProtocolException when encryption was not possible
     */
    byte[] decrypt(@NonNull String contentKey, char[] password, byte[] encryptedContent) throws EncryptionProtocolException;

    /**
     * Factory creating a new instance of {@link EncryptionProtocol}
     */
    interface Factory {

        /**
         * Creates new instance
         *
         * @param preferenceSalt to use
         * @return new instance
         */
        EncryptionProtocol create(byte[] preferenceSalt);

        /**
         * Get used digest
         *
         * @return digest impl
         */
        StringMessageDigest getStringMessageDigest();

        /**
         * Get used obfuscator
         *
         * @return obfuscator
         */
        DataObfuscator createDataObfuscator();

        /**
         * Get used secure random
         *
         * @return random gen
         */
        SecureRandom getSecureRandom();
    }
}
