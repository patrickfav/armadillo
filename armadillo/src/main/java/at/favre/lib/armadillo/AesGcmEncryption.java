package at.favre.lib.armadillo;

import android.support.annotation.Nullable;

import java.nio.ByteBuffer;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import at.favre.lib.bytes.Bytes;

/**
 * Implements AES (Advanced Encryption Standard) with Galois/Counter Mode (GCM), which is a mode of
 * operation for symmetric key cryptographic block ciphers that has been widely adopted because of
 * its efficiency and performance.
 * <p>
 * Every encryption produces a new 12 byte random IV (see http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
 * because the security of GCM depends choosing a unique initialization vector for every encryption performed with the same key.
 * <p>
 * The iv, encrypted content and auth tag will be encoded to the following format:
 * <p>
 * out = byte[] {x y y y y y y y y y y y y z z z ...}
 * <p>
 * x = IV length as byte
 * y = IV bytes
 * z = content bytes (encrypted content, auth tag)
 *
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */
@SuppressWarnings("WeakerAccess")
final class AesGcmEncryption implements AuthenticatedEncryption {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    private final SecureRandom secureRandom;
    private final Provider provider;
    private ThreadLocal<Cipher> cipherWrapper = new ThreadLocal<>();

    public AesGcmEncryption() {
        this(new SecureRandom(), null);
    }

    public AesGcmEncryption(SecureRandom secureRandom) {
        this(secureRandom, null);
    }

    public AesGcmEncryption(SecureRandom secureRandom, Provider provider) {
        this.secureRandom = secureRandom;
        this.provider = provider;
    }

    @Override
    public byte[] encrypt(byte[] rawEncryptionKey, byte[] rawData, @Nullable byte[] associatedData) throws AuthenticatedEncryptionException {
        if (rawEncryptionKey.length < 16) {
            throw new IllegalArgumentException("key length must be longer than 16 bytes");
        }

        byte[] iv = null;
        byte[] encrypted = null;
        try {
            iv = new byte[IV_LENGTH_BYTE];
            secureRandom.nextBytes(iv);

            final Cipher cipherEnc = getCipher();
            cipherEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"), new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            if (associatedData != null) {
                cipherEnc.updateAAD(associatedData);
            }

            encrypted = cipherEnc.doFinal(rawData);

            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + encrypted.length);
            byteBuffer.put((byte) iv.length);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);
            return byteBuffer.array();
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not encrypt", e);
        } finally {
            Bytes.wrapNullSafe(iv).mutable().secureWipe();
            Bytes.wrapNullSafe(encrypted).mutable().secureWipe();
        }
    }

    @Override
    public byte[] decrypt(byte[] rawEncryptionKey, byte[] encryptedData, @Nullable byte[] associatedData) throws AuthenticatedEncryptionException {
        try {
            int initialOffset = 1;
            int ivLength = encryptedData[0];

            if (ivLength != 12 && ivLength != 16) {
                throw new IllegalStateException("Unexpected iv length");
            }

            final Cipher cipherDec = getCipher();
            cipherDec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"),
                    new GCMParameterSpec(TAG_LENGTH_BIT, encryptedData, initialOffset, ivLength));

            if (associatedData != null) {
                cipherDec.updateAAD(associatedData);
            }

            return cipherDec.doFinal(encryptedData, initialOffset + ivLength, encryptedData.length - (initialOffset + ivLength));
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not decrypt", e);
        }
    }

    @Override
    public int byteSizeLength(@KeyStrength int keyStrengthType) {
        return keyStrengthType == STRENGTH_HIGH ? 16 : 32;
    }

    private Cipher getCipher() {
        Cipher cipher = cipherWrapper.get();
        if (cipher == null) {
            try {
                if (provider != null) {
                    cipher = Cipher.getInstance(ALGORITHM, provider);
                } else {
                    cipher = Cipher.getInstance(ALGORITHM);
                }
            } catch (Exception e) {
                throw new IllegalStateException("could not get cipher instance", e);
            }
            cipherWrapper.set(cipher);
            return cipherWrapper.get();
        } else {
            return cipher;
        }
    }
}
