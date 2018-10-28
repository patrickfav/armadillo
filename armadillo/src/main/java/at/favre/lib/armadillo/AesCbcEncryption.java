package at.favre.lib.armadillo;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

/**
 * Implements AES (Advanced Encryption Standard) with Cipher Block Chaining (CBC), which is a mode of
 * operation for symmetric key cryptographic block ciphers. For integrity it uses HMAC with SHA-256,
 * using the encrypt-then-mac schema.
 * <p>
 * The iv, mac and encrypted content will be encoded to the following format:
 * <p>
 * out = byte[] {x y y y y y y y y y y y y i j j ... z z z ...}
 * <p>
 * x = IV length as byte
 * y = IV bytes
 * i = mac length as byte
 * j = mac bytes
 * z = content bytes (encrypted content, auth tag)
 *
 * @deprecated this is only meant for Kitkat backwards compatibly as this version and below does not
 * support AES-GCM.
 * @author Patrick Favre-Bulle
 * @since 27.10.2018
 */
@SuppressWarnings({"WeakerAccess", "DeprecatedIsStillUsed"})
@Deprecated
final class AesCbcEncryption implements AuthenticatedEncryption {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int IV_LENGTH_BYTE = 16;

    private final SecureRandom secureRandom;
    private final Provider provider;
    private Cipher cipher;

    public AesCbcEncryption() {
        this(new SecureRandom(), null);
    }

    public AesCbcEncryption(SecureRandom secureRandom) {
        this(secureRandom, null);
    }

    public AesCbcEncryption(SecureRandom secureRandom, Provider provider) {
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
        byte[] mac = null;
        try {
            iv = new byte[IV_LENGTH_BYTE];
            secureRandom.nextBytes(iv);

            final Cipher cipherEnc = getCipher();
            cipherEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"), new IvParameterSpec(iv));

            encrypted = cipherEnc.doFinal(rawData);

            mac = macCipherText(rawEncryptionKey, encrypted, associatedData);

            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + 1 + mac.length + encrypted.length);
            byteBuffer.put((byte) iv.length);
            byteBuffer.put(iv);
            byteBuffer.put((byte) mac.length);
            byteBuffer.put(mac);
            byteBuffer.put(encrypted);
            return byteBuffer.array();
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not encrypt", e);
        } finally {
            Bytes.wrapNullSafe(iv).mutable().secureWipe();
            Bytes.wrapNullSafe(encrypted).mutable().secureWipe();
            Bytes.wrapNullSafe(mac).mutable().secureWipe();
        }
    }

    private byte[] macCipherText(byte[] rawEncryptionKey, byte[] cipherText, @Nullable byte[] associatedData) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKey macKey = createMacKey(rawEncryptionKey);

        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(macKey);

        Bytes cipherBytes = Bytes.wrap(cipherText);
        try {
            if (associatedData != null) {
                cipherBytes = cipherBytes.append(Bytes.wrap(associatedData));
            }

            return hmac.doFinal(cipherBytes.array());
        } finally {
            if (associatedData != null) {
                cipherBytes.mutable().secureWipe();
            }
        }
    }

    @NonNull
    private SecretKey createMacKey(byte[] rawEncryptionKey) {
        byte[] derivedMacKey = HKDF.fromHmacSha256().expand(rawEncryptionKey, Bytes.from("macKey").array(), 32);
        return new SecretKeySpec(derivedMacKey, HMAC_ALGORITHM);
    }

    @Override
    public byte[] decrypt(byte[] rawEncryptionKey, byte[] encryptedData, @Nullable byte[] associatedData) throws AuthenticatedEncryptionException {
        byte[] iv = null;
        byte[] mac = null;
        byte[] encrypted = null;
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

            int ivLength = byteBuffer.get();
            iv = new byte[ivLength];
            byteBuffer.get(iv);
            int macLength = byteBuffer.get();
            mac = new byte[macLength];
            byteBuffer.get(mac);

            encrypted = new byte[byteBuffer.remaining()];
            byteBuffer.get(encrypted);

            verifyMac(rawEncryptionKey, encrypted, mac, associatedData);

            final Cipher cipherDec = getCipher();
            cipherDec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"), new IvParameterSpec(iv));
            return cipherDec.doFinal(encrypted);
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not decrypt", e);
        } finally {
            Bytes.wrapNullSafe(iv).mutable().secureWipe();
            Bytes.wrapNullSafe(encrypted).mutable().secureWipe();
            Bytes.wrapNullSafe(mac).mutable().secureWipe();
        }
    }

    private void verifyMac(byte[] rawEncryptionKey, byte[] cipherText, byte[] mac, @Nullable byte[] associatedData) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] actualMac = macCipherText(rawEncryptionKey, cipherText, associatedData);
        boolean isMacEqual = Bytes.wrap(mac).equalsConstantTime(actualMac);

        if (!isMacEqual) {
            throw new SecurityException("encryption integrity exception: mac does not match");
        }
    }

    @Override
    public int byteSizeLength(@KeyStrength int keyStrengthType) {
        return keyStrengthType == STRENGTH_HIGH ? 16 : 32;
    }

    private Cipher getCipher() {
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
        }
        return cipher;
    }
}
