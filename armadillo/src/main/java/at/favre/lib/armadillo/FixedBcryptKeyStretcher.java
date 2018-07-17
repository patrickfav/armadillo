package at.favre.lib.armadillo;

import android.os.StrictMode;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;
import at.favre.lib.crypto.bcrypt.BCrypt;

/**
 * Bcrypt is a password hashing function designed by Niels Provos and David Mazières, based on the Blowfish cipher,
 * and presented at USENIX in 1999. Besides incorporating a salt to protect against rainbow table attacks, bcrypt
 * is an adaptive function: over time, the iteration count can be increased to make it slower, so it remains resistant
 * to brute-force search attacks even with increasing computation power.
 *
 * This is the second implementation providing fixes for issues present in {@link BrokenBcryptKeyStretcher}.
 * Note that this will not create compatible keys compared to the old broken implementation.
 *
 * What was fixed:
 *  - possibility to use arbitrary password length (by extracting always 71 bytes)
 *  - use of full 16 possible bytes of salt
 *
 * @author Patrick Favre-Bulle
 * @since 14.07.2017
 */

final class FixedBcryptKeyStretcher implements KeyStretchingFunction {
    private static final int BCRYPT_MIN_ROUNDS = 8;
    private static final int BCRYPT_DEFAULT_ROUNDS = 12;

    private final int iterations;

    /**
     * Creates a new instance with default rounds parameter (see {@link #BCRYPT_DEFAULT_ROUNDS})
     */
    public FixedBcryptKeyStretcher() {
        this(BCRYPT_DEFAULT_ROUNDS);
    }

    /**
     * Creates a new instance with desired rounds.
     *
     * @param log2Rounds this is the log2(Iterations). e.g. 12 ==> 2^12 = 4,096 iterations, the higher, the slower
     *                   cannot be smaller than 8 (this is a stricter requirement than the original)
     */
    public FixedBcryptKeyStretcher(int log2Rounds) {
        this.iterations = Math.max(BCRYPT_MIN_ROUNDS, log2Rounds);
    }

    @Override
    public byte[] stretch(byte[] salt, char[] password, int outLengthByte) {
        try {
            return HKDF.fromHmacSha256().expand(bcrypt(salt, password, iterations), "bcrypt".getBytes(), outLengthByte);
        } catch (Exception e) {
            throw new IllegalStateException("could not stretch with bcrypt", e);
        }
    }

    /**
     * Computes the Bcrypt hash of a password.
     *
     * @param password  the password to hash.
     * @param salt      the salt
     * @param logRounds log2(Iterations). e.g. 12 ==> 2^12 = 4,096 iterations
     * @return the Bcrypt hash of the password
     */
    private static byte[] bcrypt(byte[] salt, char[] password, int logRounds) {
        StrictMode.noteSlowCall("bcrypt is a very expensive call and should not be done on the main thread");
        byte[] passwordBytes = null;
        try {
            passwordBytes = charArrayToByteArray(password, StandardCharsets.UTF_8);
            return BCrypt.with(BCrypt.Version.VERSION_2A).hashRaw(logRounds,
                HKDF.fromHmacSha256().expand(salt, "bcrypt-salt".getBytes(), 16),
                    HKDF.fromHmacSha256().expand(passwordBytes, "bcrypt-pw".getBytes(), 71)).rawHash;
        } finally {
            Bytes.wrapNullSafe(passwordBytes).mutable().secureWipe();
        }
    }

    private static byte[] charArrayToByteArray(char[] charArray, Charset charset) {
        ByteBuffer bb = charset.encode(CharBuffer.wrap(charArray));
        byte[] bytes = new byte[bb.remaining()];
        bb.get(bytes);
        return bytes;
    }
}
