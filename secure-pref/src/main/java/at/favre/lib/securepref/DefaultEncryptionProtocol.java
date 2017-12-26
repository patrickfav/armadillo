package at.favre.lib.securepref;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.security.SecureRandom;
import java.text.Normalizer;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

/**
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

final class DefaultEncryptionProtocol implements EncryptionProtocol {

    private final byte[] preferenceSalt;
    private final EncryptionFingerprint fingerprint;
    private final KeyStretchingFunction keyStretchingFunction;
    private final SymmetricEncryption symmetricEncryption;
    private final DataObfuscator.Factory dataObfuscatorFactory;
    private final ContentKeyDigest contentKeyDigest;
    private final int keyLengthBit;

    private DefaultEncryptionProtocol(byte[] preferenceSalt, EncryptionFingerprint fingerprint,
                                      ContentKeyDigest contentKeyDigest, SymmetricEncryption symmetricEncryption,
                                      @SymmetricEncryption.KeyStrength int keyStrength, KeyStretchingFunction keyStretchingFunction,
                                      DataObfuscator.Factory dataObfuscatorFactory) {
        this.preferenceSalt = preferenceSalt;
        this.symmetricEncryption = symmetricEncryption;
        this.keyStretchingFunction = keyStretchingFunction;
        this.fingerprint = fingerprint;
        this.contentKeyDigest = contentKeyDigest;
        this.keyLengthBit = symmetricEncryption.byteSizeLength(keyStrength) * 8;
        this.dataObfuscatorFactory = dataObfuscatorFactory;
    }

    @Override
    public String deriveContentKey(String originalContentKey) {
        return contentKeyDigest.derive(Bytes.from(originalContentKey).append(preferenceSalt).encodeUtf8(), "contentKey");
    }

    @Override
    public byte[] encrypt(@NonNull String contentKey, byte[] rawContent) throws EncryptionProtocolException {
        return encrypt(contentKey, null, rawContent);
    }

    @Override
    public byte[] encrypt(@NonNull String contentKey, char[] password, byte[] rawContent) throws EncryptionProtocolException {
        byte[] fingerprintBytes = new byte[0];
        try {
            fingerprintBytes = fingerprint.getBytes();
            byte[] encrypted = symmetricEncryption.encrypt(keyDerivationFunction(contentKey, fingerprintBytes, preferenceSalt, password), rawContent);

            DataObfuscator obfuscator = dataObfuscatorFactory.create(Bytes.from(contentKey).append(fingerprintBytes).array());
            obfuscator.obfuscate(encrypted);
            obfuscator.clearKey();

            return encrypted;
        } catch (SymmetricEncryptionException e) {
            throw new EncryptionProtocolException(e);
        } finally {
            Bytes.wrap(fingerprintBytes).mutable().secureWipe();
        }
    }

    @Override
    public byte[] decrypt(@NonNull String contentKey, byte[] encryptedContent) throws EncryptionProtocolException {
        return decrypt(contentKey, null, encryptedContent);
    }

    @Override
    public byte[] decrypt(@NonNull String contentKey, char[] password, byte[] encryptedContent) throws EncryptionProtocolException {
        byte[] fingerprintBytes = new byte[0];
        try {
            fingerprintBytes = fingerprint.getBytes();

            DataObfuscator obfuscator = dataObfuscatorFactory.create(Bytes.from(contentKey).append(fingerprintBytes).array());
            obfuscator.deobfuscate(encryptedContent);
            obfuscator.clearKey();

            return symmetricEncryption.decrypt(keyDerivationFunction(contentKey, fingerprintBytes, preferenceSalt, password), encryptedContent);
        } catch (SymmetricEncryptionException e) {
            throw new EncryptionProtocolException(e);
        } finally {
            Bytes.wrap(fingerprintBytes).mutable().secureWipe();
        }
    }

    private byte[] keyDerivationFunction(String contentKey, byte[] fingerprint, byte[] preferenceSalt, @Nullable char[] password) {
        Bytes ikm = Bytes.wrap(fingerprint).append(Bytes.from(contentKey, Normalizer.Form.NFKD));

        if (password != null) {
            ikm.append(keyStretchingFunction.stretch(password, 32));
        }

        return HKDF.fromHmacSha512().extractAndExpand(preferenceSalt, ikm.array(), "DefaultEncryptionProtocol".getBytes(), keyLengthBit / 8);
    }

    public static final class Factory implements EncryptionProtocol.Factory {

        private final EncryptionFingerprint fingerprint;
        private final ContentKeyDigest contentKeyDigest;
        private final SymmetricEncryption symmetricEncryption;
        @SymmetricEncryption.KeyStrength
        private final int keyStrength;
        private final KeyStretchingFunction keyStretchingFunction;
        private final DataObfuscator.Factory dataObfuscatorFactory;
        private final SecureRandom secureRandom;

        Factory(EncryptionFingerprint fingerprint, ContentKeyDigest contentKeyDigest,
                SymmetricEncryption symmetricEncryption, int keyStrength,
                KeyStretchingFunction keyStretchingFunction, DataObfuscator.Factory dataObfuscatorFactory,
                SecureRandom secureRandom) {
            this.fingerprint = fingerprint;
            this.contentKeyDigest = contentKeyDigest;
            this.symmetricEncryption = symmetricEncryption;
            this.keyStrength = keyStrength;
            this.keyStretchingFunction = keyStretchingFunction;
            this.dataObfuscatorFactory = dataObfuscatorFactory;
            this.secureRandom = secureRandom;
        }

        @Override
        public EncryptionProtocol create(byte[] preferenceSalt) {
            return new DefaultEncryptionProtocol(preferenceSalt, fingerprint, contentKeyDigest, symmetricEncryption, keyStrength, keyStretchingFunction, dataObfuscatorFactory);
        }

        @Override
        public ContentKeyDigest getContentKeyDigest() {
            return contentKeyDigest;
        }

        @Override
        public DataObfuscator createDataObfuscator() {
            return dataObfuscatorFactory.create(fingerprint.getBytes());
        }

        @Override
        public SecureRandom getSecureRandom() {
            return secureRandom;
        }
    }
}
