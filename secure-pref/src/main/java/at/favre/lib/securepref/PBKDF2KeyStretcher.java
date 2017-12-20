package at.favre.lib.securepref;

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
    private static final byte[] SALT = new byte[]{(byte) 0xE6, 0x0C, (byte) 0xFA, 0x1E, (byte) 0xB1, 0x23, 0x6F, 0x75, 0x27, 0x75, 0x32, 0x13, 0x61, (byte) 0xAE, 0x36, (byte) 0xF9, 0x45, 0x58, 0x2B, 0x0D, (byte) 0xD6, (byte) 0xF3, 0x48, 0x3B, 0x6E, 0x78, (byte) 0x83, 0x1F, 0x5C, 0x3F, 0x1A, 0x76};
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
    public byte[] stretch(char[] password, int outLengthByte) {
        try {
            return pbkdf2(password, SALT, iterations, outLengthByte);
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
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, outBytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        return skf.generateSecret(spec).getEncoded();
    }
}
