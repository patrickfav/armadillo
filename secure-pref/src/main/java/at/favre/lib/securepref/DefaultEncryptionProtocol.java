package at.favre.lib.securepref;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.text.Normalizer;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

/**
 * @author RISE GmbH (patrick.favre@rise-world.com)
 * @since 18.12.2017
 */

class DefaultEncryptionProtocol implements EncryptionProtocol {

    private final EncryptionFingerprint fingerprint;
    private final KeyStretchingFunction keyStretchingFunction;
    private final SymmetricEncryption symmetricEncryption;
    private final int keyLengthBit;
    private final byte[] persistenceSalt;

    DefaultEncryptionProtocol(SymmetricEncryption symmetricEncryption, KeyStretchingFunction keyStretchingFunction,
                                     @SymmetricEncryption.KeyStrength int keyStrength, EncryptionFingerprint fingerprint,
                                     byte[] persistenceSalt) {
        this.symmetricEncryption = symmetricEncryption;
        this.keyStretchingFunction = keyStretchingFunction;
        this.fingerprint = fingerprint;
        this.keyLengthBit = keyStrength == SymmetricEncryption.STRENGTH_HIGH ? 128 : 256;

        if (persistenceSalt == null || persistenceSalt.length < 16) {
            throw new IllegalArgumentException("salt must not be null and greater than 16 byte");
        }

        this.persistenceSalt = persistenceSalt;
    }

    @Override
    public byte[] encrypt(@NonNull String contentKey, byte[] rawContent) throws EncryptionProtocolException {
        return encrypt(contentKey, null, rawContent);
    }

    @Override
    public byte[] encrypt(@NonNull String contentKey, char[] password, byte[] rawContent) throws EncryptionProtocolException {
        try {
            return symmetricEncryption.encrypt(keyDerivationFunction(contentKey, fingerprint, password), rawContent);
        } catch (SymmetricEncryptionException e) {
            throw new EncryptionProtocolException(e);
        }
    }

    @Override
    public byte[] decrypt(@NonNull String contentKey, byte[] encryptedContent) throws EncryptionProtocolException {
        return decrypt(contentKey, null, encryptedContent);
    }

    @Override
    public byte[] decrypt(@NonNull String contentKey, char[] password, byte[] encryptedContent) throws EncryptionProtocolException {
        try {
            return symmetricEncryption.decrypt(keyDerivationFunction(contentKey, fingerprint, password), encryptedContent);
        } catch (SymmetricEncryptionException e) {
            throw new EncryptionProtocolException(e);
        }
    }

    private byte[] keyDerivationFunction(String contentKey, EncryptionFingerprint fingerprint, @Nullable char[] password) {
        Bytes ikm = Bytes.wrap(fingerprint.getBytes()).append(Bytes.from(contentKey, Normalizer.Form.NFKD));

        if (password != null) {
            ikm.append(keyStretchingFunction.stretch(password));
        }

        return HKDF.fromHmacSha512().extractAndExpand(persistenceSalt, ikm.array(), "DefaultEncryptionProtocol".getBytes(), keyLengthBit / 8);
    }
}
