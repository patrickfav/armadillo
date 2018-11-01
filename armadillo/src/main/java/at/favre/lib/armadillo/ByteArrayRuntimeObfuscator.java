package at.favre.lib.armadillo;

import java.security.SecureRandom;

import at.favre.lib.bytes.Bytes;

/**
 * Simple wrapper for obfuscated in-memory byte array. The idea is to have some kind of data obfuscation
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

    /**
     * Wipe and overwrite the internal byte arrays
     */
    void wipe();

    final class Default implements ByteArrayRuntimeObfuscator {
        private final byte[][] data;
        private final SecureRandom secureRandom;

        Default(byte[] array, SecureRandom secureRandom) {
            this.secureRandom = secureRandom;
            int keyCount = (int) (Math.abs(Bytes.random(8).toLong()) % 9) + 1;
            this.data = new byte[keyCount + 1][];
            createAndEncrypt(secureRandom, Bytes.from(array), array.length);
        }

        private void createAndEncrypt(SecureRandom secureRandom, Bytes from, int length) {
            Bytes copy = from.mutable();
            for (int i = 0; i < data.length - 1; i++) {
                byte[] key = Bytes.random(length, secureRandom).array();
                this.data[i] = key;
                copy.xor(key);
            }
            this.data[data.length - 1] = copy.array();
        }

        @Override
        public byte[] getBytes() {
            Bytes b = Bytes.empty();
            for (int i = data.length - 1; i >= 0; i--) {
                if (b.isEmpty()) {
                    b = Bytes.from(data[i]).mutable();
                    continue;
                }
                b.xor(data[i]);
            }

            createAndEncrypt(this.secureRandom, Bytes.from(b), b.length());

            return b.array();
        }

        @Override
        public void wipe() {
            for (byte[] arr : data) {
                Bytes.wrap(arr).mutable().secureWipe();
            }
        }
    }
}
