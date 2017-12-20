package at.favre.lib.securepref;

import java.nio.ByteBuffer;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

final class AesGcmEncryption implements SymmetricEncryption {
    private static final byte PROTOCOL_VERSION = 0;
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12; //See http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

    private final SecureRandom secureRandom;
    private final Provider provider;
    private Cipher cipher;

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
    public byte[] encrypt(byte[] key, byte[] rawData) throws SymmetricEncryptionException {
        if (key.length < 16) {
            throw new IllegalArgumentException("key length must be longer than 16 byte");
        }

        try {
            byte[] iv = new byte[IV_LENGTH_BYTE];
            secureRandom.nextBytes(iv);

            final Cipher cipher = getCipher();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            byte[] encrypted = cipher.doFinal(rawData);

            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + 1 + iv.length + encrypted.length);
            byteBuffer.put(PROTOCOL_VERSION);
            byteBuffer.put((byte) iv.length);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);

            return byteBuffer.array();
        } catch (Exception e) {
            throw new SymmetricEncryptionException("could not encrypt", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] encryptedData) throws SymmetricEncryptionException {
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
            byte version = byteBuffer.get();

            if (version != PROTOCOL_VERSION) {
                throw new IllegalStateException("invalid protocol version " + version + " - cannot decrypt");
            }

            int ivLength = byteBuffer.get();
            byte[] iv = new byte[ivLength];
            byteBuffer.get(iv);
            byte[] encrypted = new byte[byteBuffer.remaining()];
            byteBuffer.get(encrypted);

            final Cipher cipher = getCipher();
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            return cipher.doFinal(encrypted);
        } catch (Exception e) {
            throw new SymmetricEncryptionException("could not decrypt", e);
        }
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
