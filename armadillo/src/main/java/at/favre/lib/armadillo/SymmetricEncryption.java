package at.favre.lib.armadillo;

import android.support.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

public interface SymmetricEncryption {
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
     * Encrypt
     *
     * @param rawEncryptionKey
     * @param rawData
     * @return
     * @throws SymmetricEncryptionException
     */
    byte[] encrypt(byte[] rawEncryptionKey, byte[] rawData) throws SymmetricEncryptionException;

    byte[] decrypt(byte[] rawEncryptionKey, byte[] encryptedData) throws SymmetricEncryptionException;

    /**
     * Get the required key size length in byte for given security strenght type
     *
     * @param keyStrengthType
     * @return required size in byte
     */
    int byteSizeLength(@KeyStrength int keyStrengthType);
}
