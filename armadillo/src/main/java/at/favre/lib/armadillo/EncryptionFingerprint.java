package at.favre.lib.armadillo;

import java.security.SecureRandom;

/**
 * A EncryptionFingerprint is a semi secret "key" which, during runtime, gathers entropy from e.g.
 * the device, system or other parts are used to create a cryptographic key with which the data is encrypted.
 * <p>
 * A good {@link EncryptionFingerprint} has the following properties
 * <p>
 * <ul>
 * <li>Hard to guess or figure by an attacker</li>
 * <li>Scopes exactly how the data should be bound (e.g. if you want to invalidate the data after OS update, include the OS version)</li>
 * <li>Data with high entropy</li>
 * </ul>
 * <p>
 * <em>Note:</em> If the fingerprint changes the data cannot be decrypted anymore.
 * <p>
 * See {@link EncryptionFingerprintFactory} for how to create such fingerprints in the Android framework.
 *
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

public interface EncryptionFingerprint {
    byte[] getBytes();

    /**
     * Default implementation of a {@link EncryptionFingerprint} with simple internal in-memory
     * data obfuscation.
     */
    final class Default implements EncryptionFingerprint {
        private final ByteArrayRuntimeObfuscator holder;

        @SuppressWarnings("WeakerAccess")
        public Default(byte[] array) {
            holder = new ByteArrayRuntimeObfuscator.Default(array, new SecureRandom());
        }

        @Override
        public byte[] getBytes() {
            return holder.getBytes();
        }
    }
}
