package at.favre.lib.armadillo;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
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
    private EncryptionProtocolConfig defaultConfig;
    private List<EncryptionProtocolConfig> additionalDecryptionConfigs;

    private final StringMessageDigest stringMessageDigest;
    private final SecureRandom secureRandom;
    private final int keyLengthBit;
    private final DerivedPasswordCache derivedPasswordCache;

    private DefaultEncryptionProtocol(EncryptionProtocolConfig defaultConfig, byte[] preferenceSalt,
                                      EncryptionFingerprint fingerprint, StringMessageDigest stringMessageDigest,
                                      SecureRandom secureRandom, boolean enableDerivedPasswordCaching,
                                      List<EncryptionProtocolConfig> additionalDecryptionConfigs) {
        this.defaultConfig = defaultConfig;
        this.preferenceSalt = preferenceSalt;
        this.fingerprint = fingerprint;
        this.stringMessageDigest = stringMessageDigest;
        this.keyLengthBit = defaultConfig.authenticatedEncryption.byteSizeLength(defaultConfig.keyStrength) * 8;
        this.secureRandom = secureRandom;
        this.derivedPasswordCache = new DerivedPasswordCache.Default(enableDerivedPasswordCaching, secureRandom);
        this.additionalDecryptionConfigs = additionalDecryptionConfigs;
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
            byte[] encrypted = defaultConfig.authenticatedEncryption.encrypt(key,
                    defaultConfig.compressor.compress(rawContent), Bytes.from(defaultConfig.protocolVersion).array());

            DataObfuscator obfuscator = defaultConfig.dataObfuscatorFactory.create(Bytes.from(contentKey).append(fingerprintBytes).array());
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
        buffer.putInt(defaultConfig.protocolVersion);
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
        if (protocolVersion == defaultConfig.protocolVersion) {
            return defaultConfig;
        }
        for (EncryptionProtocolConfig protocolConfig : additionalDecryptionConfigs) {
            if (protocolVersion == protocolConfig.protocolVersion) {
                return protocolConfig;
            }
        }

        throw new EncryptionProtocolException("illegal protocol version (" + protocolVersion + ")");
    }

    @Override
    public void setKeyStretchingFunction(@NonNull KeyStretchingFunction function) {
        defaultConfig = EncryptionProtocolConfig.newBuilder(defaultConfig)
                .keyStretchingFunction(Objects.requireNonNull(function))
                .build();
        derivedPasswordCache.wipe();
    }

    @Override
    public KeyStretchingFunction getKeyStretchingFunction() {
        return defaultConfig.keyStretchingFunction;
    }

    @Nullable
    @Override
    public ByteArrayRuntimeObfuscator obfuscatePassword(@Nullable char[] password) {
        return obfuscatePasswordInternal(password, secureRandom);
    }

    @Nullable
    @Override
    public char[] deobfuscatePassword(@Nullable ByteArrayRuntimeObfuscator obfuscated) {
        if (obfuscated == null) return null;

        CharBuffer charBuffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(obfuscated.getBytes()));

        if (charBuffer.capacity() != charBuffer.limit()) {
            char[] compacted = new char[charBuffer.remaining()];
            charBuffer.get(compacted);
            return compacted;
        }
        return charBuffer.array();
    }

    @Override
    public void wipeDerivedPasswordCache() {
        derivedPasswordCache.wipe();
    }

    private byte[] keyDerivationFunction(String contentKey, byte[] fingerprint, byte[] contentSalt, byte[] preferenceSalt, @Nullable char[] password) {
        Bytes ikm = Bytes.from(fingerprint, contentSalt, Bytes.from(contentKey, Normalizer.Form.NFKD).array());

        if (password != null) {
            byte[] stretched;
            if ((stretched = derivedPasswordCache.get(contentSalt, password)) == null) {
                stretched = defaultConfig.keyStretchingFunction.stretch(contentSalt, password, STRETCHED_PASSWORD_LENGTH_BYTES);
                derivedPasswordCache.put(contentSalt, password, stretched);
            }
            ikm = ikm.append(stretched);
        }

        return HKDF.fromHmacSha512().extractAndExpand(preferenceSalt, ikm.array(), Bytes.from("DefaultEncryptionProtocol").array(), keyLengthBit / 8);
    }

    public static final class Factory implements EncryptionProtocol.Factory {

        private final EncryptionFingerprint fingerprint;
        private final StringMessageDigest stringMessageDigest;
        private final SecureRandom secureRandom;
        private final boolean enableDerivedPasswordCaching;
        private EncryptionProtocolConfig defaultConfig;
        private final List<EncryptionProtocolConfig> additionalDecryptionConfigs;

        Factory(EncryptionProtocolConfig defaultConfig, EncryptionFingerprint fingerprint,
                StringMessageDigest stringMessageDigest, SecureRandom secureRandom,
                boolean enableDerivedPasswordCaching,
                List<EncryptionProtocolConfig> additionalDecryptionConfigs) {
            this.defaultConfig = defaultConfig;
            this.fingerprint = fingerprint;
            this.stringMessageDigest = stringMessageDigest;
            this.secureRandom = secureRandom;
            this.enableDerivedPasswordCaching = enableDerivedPasswordCaching;
            this.additionalDecryptionConfigs = additionalDecryptionConfigs;
        }

        @Override
        public EncryptionProtocol create(byte[] preferenceSalt) {
            return new DefaultEncryptionProtocol(defaultConfig, preferenceSalt, fingerprint,
                    stringMessageDigest, secureRandom, enableDerivedPasswordCaching, additionalDecryptionConfigs);
        }

        @Override
        public StringMessageDigest getStringMessageDigest() {
            return stringMessageDigest;
        }

        @Override
        public DataObfuscator createDataObfuscator() {
            return defaultConfig.dataObfuscatorFactory.create(fingerprint.getBytes());
        }

        @Override
        public SecureRandom getSecureRandom() {
            return secureRandom;
        }

        @Nullable
        @Override
        public ByteArrayRuntimeObfuscator obfuscatePassword(@Nullable char[] password) {
            return obfuscatePasswordInternal(password, secureRandom);
        }
    }

    private static ByteArrayRuntimeObfuscator obfuscatePasswordInternal(@Nullable char[] password, SecureRandom secureRandom) {
        if (password == null) return null;
        return new ByteArrayRuntimeObfuscator.Default(Bytes.from(password).array(), secureRandom);
    }
}
