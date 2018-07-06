package at.favre.lib.armadillo;

import android.support.annotation.IntDef;
import android.support.annotation.Nullable;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Authenticated encryption (AE) and authenticated encryption with associated data (AEAD, variant of AE)
 * is a form of encryption which simultaneously provides confidentiality, integrity, and authenticity assurances
 * on the data. These attributes are provided under a single, easy to use programming interface.
 * <p>
 * See: https://en.wikipedia.org/wiki/Authenticated_encryption
 *
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

public interface AuthenticatedEncryption {
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({STRENGTH_HIGH, STRENGTH_VERY_HIGH})
    @interface KeyStrength {
    }

    /**
     * High Security which is equivalent to a AES key size of 128 bit
     */
    int STRENGTH_HIGH = 0;

    /**
     * Very high security which is equivalent to a AES key size of 256 bit
     * Note: This is usually not required.
     */
    int STRENGTH_VERY_HIGH = 1;

    /**
     * Encrypts and adds a authentication tag the given content
     *
     * @param rawEncryptionKey to use as encryption key material
     * @param rawData          to encrypt
     * @param associatedData   additional data used to create the auth tag and will be subject to integrity/authentication check
     * @return encrypted content
     * @throws AuthenticatedEncryptionException if any crypto fails
     */
    byte[] encrypt(byte[] rawEncryptionKey, byte[] rawData, @Nullable byte[] associatedData) throws AuthenticatedEncryptionException;

    /**
     * Decrypt and verifies the authenticity of given encrypted data
     *
     * @param rawEncryptionKey to use as decryption key material
     * @param encryptedData    to decrypt
     * @param associatedData   additional data used to create the auth tag; must be same as provided
     *                         in the encrypt step
     * @return decrypted, original data
     * @throws AuthenticatedEncryptionException if any crypto fails
     */
    byte[] decrypt(byte[] rawEncryptionKey, byte[] encryptedData, @Nullable byte[] associatedData) throws AuthenticatedEncryptionException;

    /**
     * Get the required key size length in bytes for given security strength type
     *
     * @param keyStrengthType STRENGTH_HIGH or STRENGTH_VERY_HIGH
     * @return required size in byte
     */
    int byteSizeLength(@KeyStrength int keyStrengthType);
}
