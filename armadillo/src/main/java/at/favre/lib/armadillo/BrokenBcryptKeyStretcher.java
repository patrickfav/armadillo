package at.favre.lib.armadillo;

import android.os.StrictMode;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Locale;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;
import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCryptFormatter;
import at.favre.lib.crypto.bcrypt.Radix64Encoder;

/**
 * DO NOT USE THIS, IT HAS SERIOUS SECURITY ISSUES, USE {@link ArmadilloBcryptKeyStretcher} INSTEAD.
 * <p>
 * This is a re-implementation of the old broken bcrypt key stretcher with the new at.favre.bcrypt lib.
 * <p>
 * The issues are:
 * - only uses max 36 bytes entropy of the possible 72 bytes allowed by bcrypt
 * - only uses 11 byte entropy of the 16 byte possible salt
 * <p>
 * Note that the new {@link ArmadilloBcryptKeyStretcher} will NOT generate the same stretched key with the
 * same input parameters, therefore it is not a simple drop-in replacement. Migration is required through
 * {@link ArmadilloSharedPreferences#changePassword(char[])}.
 *
 * @author Patrick Favre-Bulle
 * @since 19.12.2017
 * @deprecated use {@link ArmadilloBcryptKeyStretcher} instead, this stretcher has security issues,
 * see https://github.com/patrickfav/armadillo/issues/16 - only use for migration
 */
@SuppressWarnings("DeprecatedIsStillUsed")
@Deprecated
final class BrokenBcryptKeyStretcher implements KeyStretchingFunction {
    private static final int BCRYPT_MIN_ROUNDS = 8;
    private static final int BCRYPT_DEFAULT_ROUNDS = 12;
    private static final BCrypt.Version CUSTOM_LEGACY_VERSION = new BCrypt.Version(new byte[] {0x32, 0x61},
            true, true, BCrypt.Version.DEFAULT_MAX_PW_LENGTH_BYTE, new CustomFormatter(new Radix64Encoder.Default(), StandardCharsets.UTF_8), BCrypt.Version.VERSION_2A.parser);
    private final int iterations;

    /**
     * Creates a new instance with default rounds parameter (see {@link #BCRYPT_DEFAULT_ROUNDS})
     */
    public BrokenBcryptKeyStretcher() {
        this(BCRYPT_DEFAULT_ROUNDS);
    }

    /**
     * Creates a new instance with desired rounds.
     *
     * @param log2Rounds this is the log2(Iterations). e.g. 12 ==> 2^12 = 4,096 iterations, the higher, the slower
     *                   cannot be smaller than 8
     */
    public BrokenBcryptKeyStretcher(int log2Rounds) {
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
        return BCrypt.with(CUSTOM_LEGACY_VERSION, new SecureRandom(), rawPassword -> Bytes.wrapNullSafe(rawPassword).copy().array()).hash(logRounds,
            createLegacySalt(salt),
            createLegacyPassword(password, salt));
    }

    private static byte[] createLegacyPassword(char[] password, byte[] salt) {
        return Bytes.from(String.valueOf(password) + Bytes.wrap(salt).encodeHex()).encodeUtf8().getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] createLegacySalt(byte[] salt) {
        String base64SaltString = Bytes.wrap(HKDF.fromHmacSha256().expand(salt, "bcrypt".getBytes(), 16)).encodeHex();
        return new Radix64Encoder.Default().decode(base64SaltString.substring(0, 22).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * A custom formatter re-implementing the behaviour of the old broken format
     */
    private static final class CustomFormatter implements BCryptFormatter {

        private final Radix64Encoder encoder;
        private final Charset defaultCharset;

        private CustomFormatter(Radix64Encoder encoder, Charset defaultCharset) {
            this.encoder = encoder;
            this.defaultCharset = defaultCharset;
        }

        @Override
        public byte[] createHashMessage(BCrypt.HashData hashData) {
            byte[] saltEncoded = encoder.encode(hashData.rawSalt);
            byte[] hashEncoded = encoder.encode(hashData.rawHash);
            byte[] costFactorBytes = String.format(Locale.US, "%02d", hashData.cost).getBytes(defaultCharset);

            try {
                ByteBuffer byteBuffer = ByteBuffer.allocate(hashData.version.versionIdentifier.length +
                    costFactorBytes.length + 3 + saltEncoded.length + hashEncoded.length);
                byteBuffer.put((byte) 0x24);
                byteBuffer.put(hashData.version.versionIdentifier);
                byteBuffer.put((byte) 0x24);
                byteBuffer.put(costFactorBytes);
                byteBuffer.put((byte) 0x24);
                byteBuffer.put(saltEncoded);
                byteBuffer.put(hashEncoded);
                return byteBuffer.array();
            } finally {
                Bytes.wrapNullSafe(saltEncoded).mutable().secureWipe();
                Bytes.wrapNullSafe(hashEncoded).mutable().secureWipe();
                Bytes.wrapNullSafe(costFactorBytes).mutable().secureWipe();
            }
        }
    }
}
