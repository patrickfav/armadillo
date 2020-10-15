package at.favre.lib.armadillo;

import android.util.LruCache;

import androidx.annotation.Nullable;

import java.security.SecureRandom;

import at.favre.lib.bytes.Bytes;

/**
 * A simple caches, that helps caching derived passwords so that not every get operation requires
 * to derive over the (expensive) key stretching function.
 */
public interface DerivedPasswordCache {

    /**
     * Get the derived bytes from given salt and password.
     *
     * @param salt the used salt for the stretching function - key part 2 of the internal key-value storage
     * @param pw   the used password - key part 2 of the internal key-value storage
     * @return the cached bytes or null of not found
     */
    @Nullable
    byte[] get(byte[] salt, char[] pw);

    /**
     * Put a new stretched password with given salt in the cache
     *
     * @param salt  the used salt for the stretching function - key part 2 of the internal key-value storage
     * @param pw    the used password - key part 2 of the internal key-value storage
     * @param value the stretched bytes
     */
    void put(byte[] salt, char[] pw, byte[] value);

    /**
     * Overwrite and remove whole cache
     */
    void wipe();

    /**
     * Standard implementation of {@link DerivedPasswordCache}
     */
    final class Default implements DerivedPasswordCache {

        private final boolean enabled;
        private final SecureRandom secureRandom;
        private final LruCache<Long, ByteArrayRuntimeObfuscator> cache;
        private long key;

        public Default(boolean enabled, SecureRandom secureRandom) {
            this.enabled = enabled;
            this.secureRandom = secureRandom;
            this.cache = new LruCache<>(12);
        }

        @Nullable
        @Override
        public byte[] get(byte[] salt, char[] rawData) {
            if (!enabled) return null;

            if (key == getPwKey(rawData)) {
                ByteArrayRuntimeObfuscator o = cache.get(getSaltKey(salt));
                return o != null ? o.getBytes() : null;
            }

            wipe();
            return null;
        }

        @Override
        public void put(byte[] salt, char[] rawData, byte[] value) {
            if (enabled) {
                long pwKey = getPwKey(rawData);
                if (pwKey != key) {
                    wipe();
                }

                key = pwKey;
                long saltKey = getSaltKey(salt);
                cache.put(saltKey, new ByteArrayRuntimeObfuscator.Default(value, secureRandom));
            }
        }

        private long getPwKey(char[] rawData) {
            return Bytes.from(rawData).hashSha256().longAt(0);
        }

        private long getSaltKey(byte[] rawData) {
            return Bytes.from(rawData).hashSha256().longAt(0);
        }

        @Override
        public void wipe() {
            key = 0;
            if (cache.snapshot() != null) {
                for (ByteArrayRuntimeObfuscator obfuscator : cache.snapshot().values()) {
                    obfuscator.wipe();
                }
            }
            cache.evictAll();
        }
    }
}
