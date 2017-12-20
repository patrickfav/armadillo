package at.favre.lib.securepref;

import java.security.SecureRandom;

/**
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

public interface EncryptionFingerprint {
    byte[] getBytes();

    final class Default implements EncryptionFingerprint {
        private final ByteArrayRuntimeObfuscator holder;

        public Default(byte[] array) {
            holder = new ByteArrayRuntimeObfuscator.Default(array, new SecureRandom());
        }

        @Override
        public byte[] getBytes() {
            return holder.getBytes();
        }
    }
}
