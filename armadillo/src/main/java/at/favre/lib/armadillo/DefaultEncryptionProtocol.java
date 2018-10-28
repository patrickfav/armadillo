package at.favre.lib.armadillo;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.List;
import java.util.Objects;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;
import timber.log.Timber;

/**
 * The Armadillo Encryption Protocol. The whole protocol logic, orchestrating all the other parts.
 * <p>
 * The rawContent, contentSalt and protocolVersion will be encoded to the following format:
 * <p>
 * out = byte[] {v v v v w x x x x x x x x x x… y y y y z z z z z z z z z z z z z z z z z z…}
 * <p>
 * v = Protocol version
 * w = Content salt length
 * x = Content salt
 * y = Encrypted content length
 * z = Encrypted content
 *
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

final class DefaultEncryptionProtocol implements EncryptionProtocol {

    private static final int CONTENT_SALT_LENGTH_BYTES = 16;
    private static final int STRETCHED_PASSWORD_LENGTH_BYTES = 32;
    private static final int PROTOCOL_VERSION_LENGTH_BYTES = 4;
    private static final int CONTENT_SALT_SIZE_LENGTH_BYTES = 1;
    private static final int ENCRYPTED_CONTENT_SIZE_LENGTH_BYTES = 4;

    private final byte[] preferenceSalt;
    private final EncryptionFingerprint fingerprint;
    private EncryptionProtocolConfig defaultEncryptionProtocol;
    private List<EncryptionProtocolConfig> supportedEncryptionProtocols;

    private final StringMessageDigest stringMessageDigest;
    private final SecureRandom secureRandom;
    private final int keyLengthBit;

    private DefaultEncryptionProtocol(EncryptionProtocolConfig defaultEncryptionProtocol, byte[] preferenceSalt,
                                      EncryptionFingerprint fingerprint, StringMessageDigest stringMessageDigest,
                                      SecureRandom secureRandom, List<EncryptionProtocolConfig> supportedEncryptionProtocols) {
        this.defaultEncryptionProtocol = defaultEncryptionProtocol;
        this.preferenceSalt = preferenceSalt;
        this.fingerprint = fingerprint;
        this.stringMessageDigest = stringMessageDigest;
        this.keyLengthBit = defaultEncryptionProtocol.authenticatedEncryption.byteSizeLength(defaultEncryptionProtocol.keyStrength) * 8;
        this.secureRandom = secureRandom;
        this.supportedEncryptionProtocols = supportedEncryptionProtocols;
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
    public byte[] encrypt(@NonNull String contentKey, @Nullable char[] password, byte[] rawContent) throws EncryptionProtocolException {
        long start = System.currentTimeMillis();
        byte[] fingerprintBytes = new byte[0];
        byte[] key = new byte[0];

        try {
            byte[] contentSalt = Bytes.random(CONTENT_SALT_LENGTH_BYTES, secureRandom).array();

            fingerprintBytes = fingerprint.getBytes();
            key = keyDerivationFunction(contentKey, fingerprintBytes, contentSalt, preferenceSalt, password);
            byte[] encrypted = defaultEncryptionProtocol.authenticatedEncryption.encrypt(key,
                    defaultEncryptionProtocol.compressor.compress(rawContent), Bytes.from(defaultEncryptionProtocol.protocolVersion).array());

            DataObfuscator obfuscator = defaultEncryptionProtocol.dataObfuscatorFactory.create(Bytes.from(contentKey).append(fingerprintBytes).array());
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
        ByteBuffer buffer = ByteBuffer.allocate(PROTOCOL_VERSION_LENGTH_BYTES
                + CONTENT_SALT_SIZE_LENGTH_BYTES + contentSalt.length
                + ENCRYPTED_CONTENT_SIZE_LENGTH_BYTES + encrypted.length);
        buffer.putInt(defaultEncryptionProtocol.protocolVersion);
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
    public byte[] decrypt(@NonNull String contentKey, @Nullable char[] password, byte[] encryptedContent) throws EncryptionProtocolException {
        long start = System.currentTimeMillis();
        byte[] fingerprintBytes = new byte[0];
        byte[] key = new byte[0];

        try {
            fingerprintBytes = fingerprint.getBytes();

            ByteBuffer buffer = ByteBuffer.wrap(encryptedContent);
            EncryptionProtocolConfig currentConfig = getConfigForDecryption(buffer.getInt());

            byte[] contentSalt = new byte[buffer.get()];
            buffer.get(contentSalt);

            byte[] encrypted = new byte[buffer.getInt()];
            buffer.get(encrypted);

            DataObfuscator obfuscator = currentConfig.dataObfuscatorFactory.create(Bytes.from(contentKey).append(fingerprintBytes).array());
            try {
                obfuscator.deobfuscate(encrypted);
            } finally {
                obfuscator.clearKey();
            }

            key = keyDerivationFunction(contentKey, fingerprintBytes, contentSalt, preferenceSalt, password);

            return currentConfig.compressor.decompress(currentConfig.authenticatedEncryption.decrypt(key, encrypted, Bytes.from(currentConfig.protocolVersion).array()));
        } catch (AuthenticatedEncryptionException e) {
            throw new EncryptionProtocolException(e);
        } finally {
            Bytes.wrap(fingerprintBytes).mutable().secureWipe();
            Bytes.wrap(key).mutable().secureWipe();
            Timber.v("decrypt took %d ms", System.currentTimeMillis() - start);
        }
    }

    @NonNull
    private EncryptionProtocolConfig getConfigForDecryption(int protocolVersion) throws EncryptionProtocolException {
        if (protocolVersion == defaultEncryptionProtocol.protocolVersion) {
            return defaultEncryptionProtocol;
        }
        for (EncryptionProtocolConfig protocolConfig : supportedEncryptionProtocols) {
            if (protocolVersion == protocolConfig.protocolVersion) {
                return protocolConfig;
            }
        }

        throw new EncryptionProtocolException("illegal protocol version (" + protocolVersion + ")");
    }

    @Override
    public void setKeyStretchingFunction(@NonNull KeyStretchingFunction function) {
        defaultEncryptionProtocol = EncryptionProtocolConfig.newBuilder(defaultEncryptionProtocol)
                .keyStretchingFunction(Objects.requireNonNull(function))
                .build();
    }

    @Override
    public KeyStretchingFunction getKeyStretchingFunction() {
        return defaultEncryptionProtocol.keyStretchingFunction;
    }

    private byte[] keyDerivationFunction(String contentKey, byte[] fingerprint, byte[] contentSalt, byte[] preferenceSalt, @Nullable char[] password) {
        Bytes ikm = Bytes.wrap(fingerprint).append(contentSalt).append(Bytes.from(contentKey, Normalizer.Form.NFKD));

        if (password != null) {
            ikm = ikm.append(defaultEncryptionProtocol.keyStretchingFunction.stretch(contentSalt, password, STRETCHED_PASSWORD_LENGTH_BYTES));
        }

        return HKDF.fromHmacSha512().extractAndExpand(preferenceSalt, ikm.array(), "DefaultEncryptionProtocol".getBytes(), keyLengthBit / 8);
    }

    public static final class Factory implements EncryptionProtocol.Factory {

        private final EncryptionFingerprint fingerprint;
        private final StringMessageDigest stringMessageDigest;
        private final SecureRandom secureRandom;
        private EncryptionProtocolConfig defaultEncryptionProtocol;
        private final List<EncryptionProtocolConfig> supportedEncryptionConfigs;

        Factory(EncryptionProtocolConfig defaultEncryptionProtocol, EncryptionFingerprint fingerprint,
                StringMessageDigest stringMessageDigest, SecureRandom secureRandom,
                List<EncryptionProtocolConfig> supportedEncryptionConfigs) {
            this.defaultEncryptionProtocol = defaultEncryptionProtocol;
            this.fingerprint = fingerprint;
            this.stringMessageDigest = stringMessageDigest;
            this.secureRandom = secureRandom;
            this.supportedEncryptionConfigs = supportedEncryptionConfigs;
        }

        @Override
        public EncryptionProtocol create(byte[] preferenceSalt) {
            return new DefaultEncryptionProtocol(defaultEncryptionProtocol, preferenceSalt, fingerprint,
                    stringMessageDigest, secureRandom, supportedEncryptionConfigs);
        }

        @Override
        public StringMessageDigest getStringMessageDigest() {
            return stringMessageDigest;
        }

        @Override
        public DataObfuscator createDataObfuscator() {
            return defaultEncryptionProtocol.dataObfuscatorFactory.create(fingerprint.getBytes());
        }

        @Override
        public SecureRandom getSecureRandom() {
            return secureRandom;
        }
    }
}
