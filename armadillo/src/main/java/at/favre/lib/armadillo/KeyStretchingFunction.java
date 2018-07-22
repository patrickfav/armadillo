package at.favre.lib.armadillo;

import android.support.annotation.Nullable;

/**
 * In cryptography, key stretching techniques are used to make a possibly weak key, typically a password or
 * passphrase, more secure against a brute-force attack by increasing the time it takes to test each possible key.
 * <p>
 * This function should implement a key derivation function with a parametrized key stretching feature.
 * <p>
 * Examples of such algorithms are:
 * <ul>
 * <li>PKDF2</li>
 * <li>Bcrypt</li>
 * <li>Scrypt</li>
 * <li>Argon2</li>
 * </ul>
 *
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

public interface KeyStretchingFunction {

    /**
     * Derives and stretches the given password with given salt to desired out length.
     *
     * @param salt          to use when deriving/stretching the password
     * @param password      to stretch
     * @param outLengthByte required out length byte
     * @return byte array with length of outLengthByte
     */
    byte[] stretch(byte[] salt, @Nullable char[] password, int outLengthByte);
}
