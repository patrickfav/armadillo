package at.favre.lib.armadillo;

import android.os.StrictMode;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * @author Patrick Favre-Bulle
 * @since 19.12.2017
 */

final class PBKDF2KeyStretcher implements KeyStretchingFunction {
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int PBKDF2_MIN_ITERATIONS = 1_000;
    private static final int PBKDF2_DEFAULT_ITERATIONS = 10_000;

    private final int iterations;

    PBKDF2KeyStretcher() {
        this(PBKDF2_DEFAULT_ITERATIONS);
    }

    PBKDF2KeyStretcher(int iterations) {
        this.iterations = Math.max(PBKDF2_MIN_ITERATIONS, iterations);
    }

    @Override
    public byte[] stretch(byte[] salt, char[] password, int outLengthByte) {
        try {
            return pbkdf2(password, salt, iterations, outLengthByte);
        } catch (Exception e) {
            throw new IllegalStateException("could not stretch with pbkdf2", e);
        }
    }

    /**
     * Computes the PBKDF2 hash of a password.
     *
     * @param password   the password to hash.
     * @param salt       the salt
     * @param iterations the iteration count (slowness factor)
     * @param outBytes   the length of the hash to compute in bytes
     * @return the PBDKF2 hash of the password
     */
    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int outBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        StrictMode.noteSlowCall("pbkdf2 is a very expensive call and should not be done on the main thread");
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, outBytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        return skf.generateSecret(spec).getEncoded();
    }
}
