package at.favre.lib.securepref;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.text.Normalizer;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

/**
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

final class DefaultEncryptionProtocol implements EncryptionProtocol {

    private final EncryptionFingerprint fingerprint;
    private final KeyStretchingFunction keyStretchingFunction;
    private final SymmetricEncryption symmetricEncryption;
    private final DataObfuscator.Factory dataObfuscatorFactory;
    private final int keyLengthBit;

    DefaultEncryptionProtocol(SymmetricEncryption symmetricEncryption, KeyStretchingFunction keyStretchingFunction,
                              @SymmetricEncryption.KeyStrength int keyStrength, EncryptionFingerprint fingerprint,
                              DataObfuscator.Factory dataObfuscatorFactory) {
        this.symmetricEncryption = symmetricEncryption;
        this.keyStretchingFunction = keyStretchingFunction;
        this.fingerprint = fingerprint;
        this.keyLengthBit = symmetricEncryption.byteSizeLength(keyStrength) * 8;
        this.dataObfuscatorFactory = dataObfuscatorFactory;
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
            byte[] encrypted = symmetricEncryption.encrypt(keyDerivationFunction(contentKey, fingerprintBytes, password), rawContent);

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

            return symmetricEncryption.decrypt(keyDerivationFunction(contentKey, fingerprintBytes, password), encryptedContent);
        } catch (SymmetricEncryptionException e) {
            throw new EncryptionProtocolException(e);
        } finally {
            Bytes.wrap(fingerprintBytes).mutable().secureWipe();
        }
    }

    @Override
    public DataObfuscator createDataObfuscator(@NonNull byte[] key) {
        return dataObfuscatorFactory.create(key);
    }

    @Override
    public EncryptionFingerprint getFingerprint() {
        return fingerprint;
    }

    private byte[] keyDerivationFunction(String contentKey, byte[] fingerprint, @Nullable char[] password) {
        Bytes ikm = Bytes.wrap(fingerprint).append(Bytes.from(contentKey, Normalizer.Form.NFKD));

        if (password != null) {
            ikm.append(keyStretchingFunction.stretch(password, 32));
        }

        return HKDF.fromHmacSha512().extractAndExpand(new byte[64], ikm.array(), "DefaultEncryptionProtocol".getBytes(), keyLengthBit / 8);
    }
}
