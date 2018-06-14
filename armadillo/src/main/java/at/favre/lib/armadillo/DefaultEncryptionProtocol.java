package at.favre.lib.armadillo;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.text.Normalizer;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;
import timber.log.Timber;

/**
 * The Armadillo Encryption Protocol. The whole protocol logic, orchestrating all the other parts.
 *
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

final class DefaultEncryptionProtocol implements EncryptionProtocol {
    private final byte[] preferenceSalt;
    private final EncryptionFingerprint fingerprint;
    private final KeyStretchingFunction keyStretchingFunction;
    private final AuthenticatedEncryption authenticatedEncryption;
    private final DataObfuscator.Factory dataObfuscatorFactory;
    private final StringMessageDigest stringMessageDigest;
    private final Compressor compressor;
    private final SecureRandom secureRandom;
    private final int keyLengthBit;
    private final int protocolVersion;

    private DefaultEncryptionProtocol(int protocolVersion, byte[] preferenceSalt, EncryptionFingerprint fingerprint,
                                      StringMessageDigest stringMessageDigest, AuthenticatedEncryption authenticatedEncryption,
                                      @AuthenticatedEncryption.KeyStrength int keyStrength, KeyStretchingFunction keyStretchingFunction,
                                      DataObfuscator.Factory dataObfuscatorFactory, SecureRandom secureRandom, Compressor compressor) {
        this.protocolVersion = protocolVersion;
        this.preferenceSalt = preferenceSalt;
        this.authenticatedEncryption = authenticatedEncryption;
        this.keyStretchingFunction = keyStretchingFunction;
        this.fingerprint = fingerprint;
        this.stringMessageDigest = stringMessageDigest;
        this.compressor = compressor;
        this.keyLengthBit = authenticatedEncryption.byteSizeLength(keyStrength) * 8;
        this.dataObfuscatorFactory = dataObfuscatorFactory;
        this.secureRandom = secureRandom;
    }

    @Override
    public String deriveContentKey(String originalContentKey) {
        return stringMessageDigest.derive(Bytes.from(originalContentKey).append(preferenceSalt).encodeUtf8(), "contentKey");
    }

    @Override
    public byte[] encrypt(@NonNull String contentKey, byte[] rawContent) throws EncryptionProtocolException {
        return encrypt(contentKey, null, rawContent);
    }

    @Override
    public byte[] encrypt(@NonNull String contentKey, char[] password, byte[] rawContent) throws EncryptionProtocolException {
        long start = System.currentTimeMillis();
        byte[] fingerprintBytes = new byte[0];
        byte[] key = new byte[0];

        try {
            byte[] contentSalt = Bytes.random(16, secureRandom).array();

            fingerprintBytes = fingerprint.getBytes();
            key = keyDerivationFunction(contentKey, fingerprintBytes, contentSalt, preferenceSalt, password);
            byte[] encrypted = authenticatedEncryption.encrypt(key, compressor.compress(rawContent), Bytes.from(protocolVersion).array());

            DataObfuscator obfuscator = dataObfuscatorFactory.create(Bytes.from(contentKey).append(fingerprintBytes).array());
            try {
                obfuscator.obfuscate(encrypted);
            } finally {
                obfuscator.clearKey();
            }

            return encode(contentSalt, encrypted);
        } catch (AuthenticatedEncryptionException e) {
            throw new EncryptionProtocolException(e);
        } finally {
            Bytes.wrap(fingerprintBytes).mutable().secureWipe();
            Bytes.wrap(key).mutable().secureWipe();
            Timber.v("encrypt took %d ms", System.currentTimeMillis() - start);
        }
    }

    private byte[] encode(byte[] contentSalt, byte[] encrypted) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + 1 + contentSalt.length + 4 + encrypted.length);
        buffer.putInt(protocolVersion);
        buffer.put((byte) contentSalt.length);
        buffer.put(contentSalt);
        buffer.putInt(encrypted.length);
        buffer.put(encrypted);
        return buffer.array();
    }

    @Override
    public byte[] decrypt(@NonNull String contentKey, byte[] encryptedContent) throws EncryptionProtocolException {
        return decrypt(contentKey, null, encryptedContent);
    }

    @Override
    public byte[] decrypt(@NonNull String contentKey, char[] password, byte[] encryptedContent) throws EncryptionProtocolException {
        long start = System.currentTimeMillis();
        byte[] fingerprintBytes = new byte[0];
        byte[] key = new byte[0];

        try {
            fingerprintBytes = fingerprint.getBytes();

            ByteBuffer buffer = ByteBuffer.wrap(encryptedContent);
            if (buffer.getInt() != protocolVersion) {
                throw new SecurityException("illegal protocol version");
            }

            byte[] contentSalt = new byte[buffer.get()];
            buffer.get(contentSalt);

            byte[] encrypted = new byte[buffer.getInt()];
            buffer.get(encrypted);

            DataObfuscator obfuscator = dataObfuscatorFactory.create(Bytes.from(contentKey).append(fingerprintBytes).array());
            obfuscator.deobfuscate(encrypted);
            obfuscator.clearKey();
            key = keyDerivationFunction(contentKey, fingerprintBytes, contentSalt, preferenceSalt, password);

            return compressor.decompress(authenticatedEncryption.decrypt(key, encrypted, Bytes.from(protocolVersion).array()));
        } catch (AuthenticatedEncryptionException e) {
            throw new EncryptionProtocolException(e);
        } finally {
            Bytes.wrap(fingerprintBytes).mutable().secureWipe();
            Bytes.wrap(key).mutable().secureWipe();
            Timber.v("decrypt took %d ms", System.currentTimeMillis() - start);
        }
    }

    private byte[] keyDerivationFunction(String contentKey, byte[] fingerprint, byte[] contentSalt, byte[] preferenceSalt, @Nullable char[] password) {
        Bytes ikm = Bytes.wrap(fingerprint).append(contentSalt).append(Bytes.from(contentKey, Normalizer.Form.NFKD));

        if (password != null) {
            ikm.append(keyStretchingFunction.stretch(contentSalt, password, 32));
        }

        return HKDF.fromHmacSha512().extractAndExpand(preferenceSalt, ikm.array(), "DefaultEncryptionProtocol".getBytes(), keyLengthBit / 8);
    }

    public static final class Factory implements EncryptionProtocol.Factory {

        private final int protocolVersion;
        private final EncryptionFingerprint fingerprint;
        private final StringMessageDigest stringMessageDigest;
        private final AuthenticatedEncryption authenticatedEncryption;
        @AuthenticatedEncryption.KeyStrength
        private final int keyStrength;
        private final KeyStretchingFunction keyStretchingFunction;
        private final DataObfuscator.Factory dataObfuscatorFactory;
        private final SecureRandom secureRandom;
        private final Compressor compressor;

        Factory(int protocolVersion, EncryptionFingerprint fingerprint, StringMessageDigest stringMessageDigest,
                AuthenticatedEncryption authenticatedEncryption, int keyStrength,
                KeyStretchingFunction keyStretchingFunction, DataObfuscator.Factory dataObfuscatorFactory,
                SecureRandom secureRandom, @Nullable Compressor compressor) {
            this.protocolVersion = protocolVersion;
            this.fingerprint = fingerprint;
            this.stringMessageDigest = stringMessageDigest;
            this.authenticatedEncryption = authenticatedEncryption;
            this.keyStrength = keyStrength;
            this.keyStretchingFunction = keyStretchingFunction;
            this.dataObfuscatorFactory = dataObfuscatorFactory;
            this.secureRandom = secureRandom;
            this.compressor = compressor;
        }

        @Override
        public EncryptionProtocol create(byte[] preferenceSalt) {
            return new DefaultEncryptionProtocol(protocolVersion, preferenceSalt, fingerprint, stringMessageDigest, authenticatedEncryption, keyStrength, keyStretchingFunction, dataObfuscatorFactory, secureRandom, compressor);
        }

        @Override
        public StringMessageDigest getStringMessageDigest() {
            return stringMessageDigest;
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
