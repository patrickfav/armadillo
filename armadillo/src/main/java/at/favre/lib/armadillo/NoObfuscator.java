package at.favre.lib.armadillo;

import android.support.annotation.NonNull;

/**
 * A simple No-Op implementation for {@link DataObfuscator}. Use this for testing purpose.
 *
 * @author Patrick Favre-Bulle
 */

public final class NoObfuscator implements DataObfuscator {
    @Override
    public void obfuscate(@NonNull byte[] original) {
        //no-op
    }

    @Override
    public void deobfuscate(@NonNull byte[] obfuscated) {
        //no-op
    }

    @Override
    public void clearKey() {
        //no-op
    }

    public static final class Factory implements DataObfuscator.Factory {
        @Override
        public DataObfuscator create(byte[] key) {
            return new NoObfuscator();
        }
    }
}
