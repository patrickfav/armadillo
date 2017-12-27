package at.favre.lib.armadillo;

import android.os.StrictMode;
import android.support.annotation.Nullable;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * In cryptography, PBKDF2 (Password-Based Key Derivation Function 2) are key derivation
 * functions with a sliding computational cost, aimed to reduce the vulnerability of encrypted keys
 * to brute force attacks. PBKDF2 is part of RSA Laboratories' Public-Key Cryptography Standards (PKCS)
 * series, specifically PKCS #5 v2.0, also published as Internet Engineering Task Force's RFC 2898.
 * <p>
 * This uses SHA1 as the underlying cryptographic hash functions, since SHA256+ are usually not
 * provided by standard JCA providers in Android.
 *
 * @author Patrick Favre-Bulle
 * @since 19.12.2017
 */

public final class PBKDF2KeyStretcher implements KeyStretchingFunction {
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int PBKDF2_MIN_ITERATIONS = 1_000;
    private static final int PBKDF2_DEFAULT_ITERATIONS = 10_000;

    private final int iterations;
    private final Provider provider;

    /**
     * Create a new instance with default iteration count (see {@link #PBKDF2_DEFAULT_ITERATIONS}
     */
    public PBKDF2KeyStretcher() {
        this(PBKDF2_DEFAULT_ITERATIONS, null);
    }

    /**
     * Creates a new instance. See https://cryptosense.com/parameter-choice-for-pbkdf2/ for
     * idea on what iteration count to choose
     *
     * @param iterations computational cost
     * @param provider   optional security provider (might be null if default should be chosen)
     */
    public PBKDF2KeyStretcher(int iterations, @Nullable Provider provider) {
        this.iterations = Math.max(PBKDF2_MIN_ITERATIONS, iterations);
        this.provider = provider;
    }

    @Override
    public byte[] stretch(byte[] salt, char[] password, int outLengthByte) {
        try {
            return pbkdf2(provider, password, salt, iterations, outLengthByte);
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
    private static byte[] pbkdf2(Provider provider, char[] password, byte[] salt, int iterations, int outBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        StrictMode.noteSlowCall("pbkdf2 is a very expensive call and should not be done on the main thread");
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, outBytes * 8);
        SecretKeyFactory skf = provider != null ? SecretKeyFactory.getInstance(PBKDF2_ALGORITHM, provider) : SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        return skf.generateSecret(spec).getEncoded();
    }
}
