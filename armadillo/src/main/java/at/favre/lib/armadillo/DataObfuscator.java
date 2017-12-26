package at.favre.lib.armadillo;

import android.support.annotation.NonNull;

/**
 * Data obfuscation which obfuscates the given byte arrays.
 * Obfuscation is the deliberate act of creating data that is difficult for humans to understand.
 * It is not cryptographic encryption.
 */
public interface DataObfuscator {
    /**
     * Obfuscates the given byte array. This will directly use the same array as given by the
     * parameter. The output has the same length as the input.
     *
     * @param original out parameter
     */
    void obfuscate(@NonNull byte[] original);

    /**
     * De-Obfuscates the given byte array. This will directly use the same array as given by the
     * parameter. The output has the same length as the input.
     *
     * @param obfuscated out parameter
     */
    void deobfuscate(@NonNull byte[] obfuscated);

    /**
     * Clears the internal key reference
     */
    void clearKey();

    /**
     * Factory method for obfuscator
     */
    interface Factory {

        /**
         * Creates a new data obfuscator with given key
         *
         * @param key can be used to key the obfuscator's output
         * @return new instance
         */
        DataObfuscator create(byte[] key);
    }
}
