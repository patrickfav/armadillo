package at.favre.lib.armadillo;

import android.support.annotation.NonNull;

/**
 *
 * @since 25.12.2017
 */

public class NoObfuscator implements DataObfuscator {
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
