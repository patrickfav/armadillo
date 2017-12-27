package at.favre.lib.armadillo;

import java.security.SecureRandom;

import at.favre.lib.bytes.Bytes;

/**
 * Simple wrapper for obfuscated byte array. The idea is to have some kind of data obfuscation
 * during runtime, to make it harder to read the content when instrumenting or doing a memory
 * dump. This uses a very simple and fast xor encryption and stores the encrypted data and
 * the key as fields in a 2d byte array.
 *
 * @author Patrick Favre-Bulle
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

        Default(byte[] array, SecureRandom secureRandom) {
            byte[] key = Bytes.random(array.length, secureRandom).array();
            this.data = new byte[][]{key, Bytes.wrap(array).mutable().xor(key).array()};
        }

        @Override
        public byte[] getBytes() {
            return Bytes.wrap(data[0]).xor(data[1]).array();
        }
    }
}
