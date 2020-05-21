package at.favre.lib.armadillo;

import android.os.StrictMode;
import androidx.annotation.NonNull;

import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

import static org.junit.Assert.assertArrayEquals;

/**
 * Test to check if the re-implementation of the old broken bcrypt key stretcher behaves exactly
 * the same as with the new one.
 */
public class BrokenBcryptKeyStretcherTest {

    @Test
    public void testBcrypt() {
        for (int i = 4; i < 10; i++) {
            compareLegacyFallbackImpl(i, 8, 8);
            compareLegacyFallbackImpl(i, 16, 16);
            compareLegacyFallbackImpl(i, 32, 16);
            compareLegacyFallbackImpl(i, 32, 32);
            compareLegacyFallbackImpl(i, 64, 32);
            compareLegacyFallbackImpl(i, 64, 64);
            compareLegacyFallbackImpl(i, 128, 128);
            compareLegacyFallbackImpl(i, 4, 128);
            compareLegacyFallbackImpl(i, 128, 4);
            compareLegacyFallbackImpl(i, 64, 16);
        }
    }

    private void compareLegacyFallbackImpl(int cost, int saltLength, int pwByteLength) {
        byte[] salt = Bytes.random(saltLength).array();
        char[] pw = Bytes.random(pwByteLength).encodeBase64().toCharArray();
        KeyStretchingFunction b1 = new LegacyBrokenJBcryptKeyStretcher(cost);
        KeyStretchingFunction b2 = new BrokenBcryptKeyStretcher(cost);

        byte[] out1 = b1.stretch(salt, pw, 16);
        byte[] out2 = b2.stretch(salt, pw, 16);

        assertArrayEquals(String.format("Hashes do not match\n%s\nvs\n%s", Bytes.wrap(out1).encodeHex(), Bytes.wrap(out2).encodeHex()), out1, out2);
    }

    /**
     * This is the old broken implementation of Bcrypt key stretcher as reference
     *
     * @deprecated this is only for testing purpose
     */
    @SuppressWarnings("DeprecatedIsStillUsed")
    @Deprecated
    static final class LegacyBrokenJBcryptKeyStretcher implements KeyStretchingFunction {
        private static final int BCRYPT_MIN_ROUNDS = 8;
        private final int iterations;

        /**
         * Creates a new instance with desired rounds.
         *
         * @param log2Rounds this is the log2(Iterations). e.g. 12 ==> 2^12 = 4,096 iterations, the higher, the slower
         *                   cannot be smaller than 8
         */
        LegacyBrokenJBcryptKeyStretcher(int log2Rounds) {
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
        private static byte[] bcrypt(char[] password, byte[] salt, int logRounds) {
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
}
