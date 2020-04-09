package at.favre.lib.armadillo;

import java.util.Objects;

/**
 * An encryption protocol config encapsulates all configuration needed for encryption and decryption of
 * content.
 *
 * @since 28.10.2018
 */
@SuppressWarnings("WeakerAccess")
public final class EncryptionProtocolConfig {

    public final int protocolVersion;

    public final AuthenticatedEncryption authenticatedEncryption;

    @AuthenticatedEncryption.KeyStrength
    public final int keyStrength;

    public final KeyStretchingFunction keyStretchingFunction;

    public final DataObfuscator.Factory dataObfuscatorFactory;

    public final Compressor compressor;

    private EncryptionProtocolConfig(Builder builder) {
        protocolVersion = builder.protocolVersion;
        authenticatedEncryption = builder.authenticatedEncryption;
        keyStrength = builder.keyStrength;
        keyStretchingFunction = builder.keyStretchingFunction;
        dataObfuscatorFactory = builder.dataObfuscatorFactory;
        compressor = builder.compressor;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static Builder newBuilder(EncryptionProtocolConfig copy) {
        Builder builder = new Builder();
        builder.protocolVersion = copy.protocolVersion;
        builder.authenticatedEncryption = copy.authenticatedEncryption;
        builder.keyStrength = copy.keyStrength;
        builder.keyStretchingFunction = copy.keyStretchingFunction;
        builder.dataObfuscatorFactory = copy.dataObfuscatorFactory;
        builder.compressor = copy.compressor;
        return builder;
    }

    public static Builder newDefaultConfig() {
        return newBuilder()
                .protocolVersion(Armadillo.DEFAULT_PROTOCOL_VERSION)
                .keyStretchingFunction(new ArmadilloBcryptKeyStretcher())
                .keyStrength(AuthenticatedEncryption.STRENGTH_HIGH)
                .compressor(new DisabledCompressor())
                .dataObfuscatorFactory(new HkdfXorObfuscator.Factory());
    }

    public static final class Builder {
        private int protocolVersion;
        private AuthenticatedEncryption authenticatedEncryption;
        @AuthenticatedEncryption.KeyStrength
        private int keyStrength = AuthenticatedEncryption.STRENGTH_HIGH;
        private KeyStretchingFunction keyStretchingFunction;
        private DataObfuscator.Factory dataObfuscatorFactory;
        private Compressor compressor;

        private Builder() {
        }

        /**
         * A custom crypto protocol version can be set, to be able to migrate the data.
         * <p>
         * The protocol version will be used as additional associated data with the authenticated encryption.
         *
         * @param protocolVersion to persist with the data
         * @return builder
         */
        public Builder protocolVersion(int protocolVersion) {
            this.protocolVersion = protocolVersion;
            return this;
        }

        /**
         * Set your own implementation of {@link AuthenticatedEncryption}.
         * <p>
         * Only set if you know what you are doing.
         *
         * @param authenticatedEncryption to be used
         * @return builder
         */
        public Builder authenticatedEncryption(AuthenticatedEncryption authenticatedEncryption) {
            this.authenticatedEncryption = authenticatedEncryption;
            return this;
        }

        /**
         * Set the key length for the symmetric encryption.
         * <p>
         * Currently there are 2 options:
         * <p>
         * <ul>
         * <li>HIGH - is (or comparable) to AES with 128 bit key length</li>
         * <li>VERY HIGH - is (or comparable) to AES with 256 bit key length</li>
         * </ul>
         * <p>
         * <em>Note:</em> Usually there is no real advantage to set it to VERY HIGH as HIGH (128 bit key
         * length) is fully secure for the foreseeable future. VERY HIGH only adds more security margin
         * for possible quantum computer attacks (but if you are a user which is threatened by these
         * kinds of attacks you probably require higher degrees af protection)
         *
         * @param keyStrength HIGH (default) or VERY HIGH
         * @return builder
         */
        public Builder keyStrength(@AuthenticatedEncryption.KeyStrength int keyStrength) {
            this.keyStrength = keyStrength;
            return this;
        }

        /**
         * Set a different key derivation function for provided password. If you want
         * to use a different function (e.g. scrypt) set the implementation here.
         * <p>
         * If you want to disable the key stretching feature you might use {@link FastKeyStretcher} here.
         *
         * @param keyStretchingFunction to be used
         * @return builder
         */
        public Builder keyStretchingFunction(KeyStretchingFunction keyStretchingFunction) {
            this.keyStretchingFunction = keyStretchingFunction;
            return this;
        }

        /**
         * Set your own data obfuscation implementation. Data obfuscation is used to disguise the
         * persistence data format.
         * <p>
         * Only set if you know what you are doing.
         *
         * @param dataObfuscatorFactory that creates a obfuscator with given key
         * @return builder
         */
        public Builder dataObfuscatorFactory(DataObfuscator.Factory dataObfuscatorFactory) {
            this.dataObfuscatorFactory = dataObfuscatorFactory;
            return this;
        }

        /**
         * Set compressor to be used before encryption.
         *
         * @param compressor to set
         * @return builder
         */
        public Builder compressor(Compressor compressor) {
            this.compressor = compressor;
            return this;
        }

        /**
         * Create new config instance
         *
         * @return config
         */
        public EncryptionProtocolConfig build() {
            Objects.requireNonNull(keyStretchingFunction);
            Objects.requireNonNull(dataObfuscatorFactory);
            return new EncryptionProtocolConfig(this);
        }
    }
}
