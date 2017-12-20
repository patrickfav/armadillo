package at.favre.lib.securepref;

import android.support.annotation.NonNull;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

/**
 * Created by patri on 20.12.2017.
 */
public class HkdfXorObfuscator implements DataObfuscator {
    private final static int BLOCK_SIZE_BYTE = 24;

    private final byte[] key;

    HkdfXorObfuscator(byte[] key) {
        this.key = key;
    }

    @Override
    public void obfuscate(@NonNull byte[] original) {
        Objects.requireNonNull(original);
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

    public static final class Factory implements DataObfuscator.Factory {

        @Override
        public DataObfuscator create(byte[] key) {
            return new HkdfXorObfuscator(key);
        }
    }
}
