package at.favre.lib.securepref;

import android.support.annotation.NonNull;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

/**
 * A simple obfuscator using HKDF to derive keys for individual blocks and uses
 * a simple version of CTR block mode. Uses XOR as the encryption primitive.
 *
 * The main design choices for this obfuscator:
 * <ul>
 *     <li>Non-Standard implementation and concept</li>
 *     <li>Simple and fast (using xor)</li>
 * </ul>
 *
 * This is optimized to be fast and not as secure as possible.
 */
public class HkdfXorObfuscator implements DataObfuscator {
    private final static int BLOCK_SIZE_BYTE = 128;

    private final byte[] key;

    HkdfXorObfuscator(byte[] key) {
        this.key = key;
    }

    @Override
    public void obfuscate(@NonNull byte[] original) {
        Objects.requireNonNull(original);
        Objects.requireNonNull(this.key);

        byte[] okm = HKDF.fromHmacSha512().extract(new byte[64], key);

        int ctr = 0;
        int byteIter = 0;
        ByteBuffer buffer = ByteBuffer.wrap(original);
        byte[] temp;
        byte[] roundKey;
        while (buffer.hasRemaining()) {
            temp = new byte[Math.min(BLOCK_SIZE_BYTE, buffer.remaining())];
            roundKey = HKDF.fromHmacSha512().expand(okm, Bytes.from(ctr++).array(), temp.length);
            buffer.get(temp);

            for (int i = 0; i < temp.length; i++) {
                original[byteIter++] = (byte) (temp[i] ^ roundKey[i]);
            }
            Arrays.fill(temp, (byte) 0);
            Arrays.fill(roundKey, (byte) 0);
        }

        Arrays.fill(okm, (byte) 0);
    }

    @Override
    public void deobfuscate(@NonNull byte[] obfuscated) {
        obfuscate(obfuscated);
    }

    @Override
    public void clearKey() {
        Bytes.wrap(key).mutable().secureWipe();
    }

    public static final class Factory implements DataObfuscator.Factory {

        @Override
        public DataObfuscator create(byte[] key) {
            return new HkdfXorObfuscator(key);
        }
    }
}
