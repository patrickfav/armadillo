package at.favre.lib.armadillo;

import android.os.StrictMode;
import android.support.annotation.NonNull;

import org.mindrot.jbcrypt.BCrypt;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

/**
 * Bcrypt is a password hashing function designed by Niels Provos and David Mazières, based on the Blowfish cipher,
 * and presented at USENIX in 1999. Besides incorporating a salt to protect against rainbow table attacks, bcrypt
 * is an adaptive function: over time, the iteration count can be increased to make it slower, so it remains resistant
 * to brute-force search attacks even with increasing computation power.
 *
 * @author Patrick Favre-Bulle
 * @since 19.12.2017
 */

final class BcryptKeyStretcher implements KeyStretchingFunction {
    private static final int BCRYPT_MIN_ROUNDS = 8;
    private static final int BCRYPT_DEFAULT_ROUNDS = 12;

    private final int iterations;

    /**
     * Creates a new instance with default rounds parameter (see {@link #BCRYPT_DEFAULT_ROUNDS})
     */
    BcryptKeyStretcher() {
        this(BCRYPT_DEFAULT_ROUNDS);
    }

    /**
     * Creates a new instance with desired rounds.
     *
     * @param log2Rounds this is the log2(Iterations). e.g. 12 ==> 2^12 = 4,096 iterations, the higher, the slower
     *                   cannot be smaller than 8
     */
    BcryptKeyStretcher(int log2Rounds) {
        this.iterations = Math.max(BCRYPT_MIN_ROUNDS, log2Rounds);
    }

    @Override
    public byte[] stretch(byte[] salt, char[] password, int outLengthByte) {
        try {
            return HKDF.fromHmacSha256().expand(bcrypt(password, salt, iterations), "bcrypt".getBytes(), outLengthByte);
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
    private static byte[] bcrypt(char[] password, byte[] salt, int logRounds) throws NoSuchAlgorithmException, InvalidKeySpecException {
        StrictMode.noteSlowCall("bcrypt is a very expensive call and should not be done on the main thread");
        return Bytes.from(BCrypt.hashpw(String.valueOf(password) + Bytes.wrap(salt).encodeHex(), generateSalt(salt, logRounds))).array();
    }

    @NonNull
    private static String generateSalt(byte[] salt, int logRounds) {
        StringBuilder saltBuilder = new StringBuilder();
        saltBuilder.append("$2a$");
        if (logRounds < 10) {
            saltBuilder.append("0");
        }
        if (logRounds > 30) {
            throw new IllegalArgumentException("log_rounds exceeds maximum (30)");
        }
        saltBuilder.append(Integer.toString(logRounds));
        saltBuilder.append("$");
        saltBuilder.append(Bytes.wrap(HKDF.fromHmacSha256().expand(salt, "bcrypt".getBytes(), 16)).encodeHex());
        return saltBuilder.toString();
    }
}
