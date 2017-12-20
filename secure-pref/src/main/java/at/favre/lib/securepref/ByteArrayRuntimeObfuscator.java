package at.favre.lib.securepref;

import java.security.SecureRandom;

import at.favre.lib.bytes.Bytes;

/**
 * Created by patri on 20.12.2017.
 */

public interface ByteArrayRuntimeObfuscator {

    /**
     * Get an de-obfuscated <strong>copy</strong> of the original data.
     * The value therefore may be destroyed after usage
     *
     * @return copy of the original array
     */
    byte[] getBytes();

    final class Default implements ByteArrayRuntimeObfuscator {

        private final byte[][] data;

        public Default(byte[] array, SecureRandom secureRandom) {
            byte[] key = Bytes.random(array.length, secureRandom).array();
            this.data = new byte[][] {key, Bytes.wrap(array).mutable().xor(key).array()};
        }

        @Override
        public byte[] getBytes() {
            return Bytes.wrap(data[0]).xor(data[1]).array();
        }
    }
}
