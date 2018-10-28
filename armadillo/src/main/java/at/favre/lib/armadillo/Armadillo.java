package at.favre.lib.armadillo;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.support.annotation.Nullable;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import at.favre.lib.bytes.Bytes;

/**
 * The main API of this library.
 *
 * @since 26.12.2017
 */

@SuppressWarnings("WeakerAccess")
public final class Armadillo {
    public static final int CONTENT_KEY_OUT_BYTE_LENGTH = 20;
    public static final int DEFAULT_PROTOCOL_VERSION = 0;
    public static final int KITKAT_PROTOCOL_VERSION = -19;

    private Armadillo() {
    }

    public static Builder create(SharedPreferences sharedPreferences) {
        return new Builder(sharedPreferences);
    }

    public static Builder create(Context context, String prefName) {
        return new Builder(context, prefName);
    }

    public static final class Builder {

        private final SharedPreferences sharedPreferences;
        private final Context context;
        private final String prefName;

        private EncryptionFingerprint fingerprint;
        private StringMessageDigest stringMessageDigest = new HkdfMessageDigest(BuildConfig.PREF_SALT, CONTENT_KEY_OUT_BYTE_LENGTH);
        private EncryptionProtocolConfig.Builder defaultConfig = EncryptionProtocolConfig.newDefaultConfig();
        private List<EncryptionProtocolConfig> additionalDecryptionConfigs = new ArrayList<>(2);
        private SecureRandom secureRandom = new SecureRandom();
        private RecoveryPolicy recoveryPolicy = new RecoveryPolicy.Default(true, false);
        private char[] password;
        private Provider provider;
        private boolean enableKitKatSupport = false;

        private Builder(SharedPreferences sharedPreferences) {
            this(sharedPreferences, null, null);
        }

        private Builder(Context context, String prefName) {
            this(null, context, prefName);
        }

        private Builder(SharedPreferences sharedPreferences, Context context, String prefName) {
            this.sharedPreferences = sharedPreferences;
            this.context = context;
            this.prefName = prefName;
        }

        public Builder encryptionFingerprint(Context context) {
            return encryptionFingerprint(context, (String[]) null);
        }

        public Builder encryptionFingerprint(Context context, byte[] additionalData) {
            return encryptionFingerprint(context, Bytes.wrap(additionalData).encodeBase64());
        }

        public Builder encryptionFingerprint(Context context, @Nullable String... additionalData) {
            Objects.requireNonNull(context);

            StringBuilder data = new StringBuilder();
            if (additionalData != null) {
                for (String additionalDatum : additionalData) {
                    data.append(additionalDatum);
                }
            }

            this.fingerprint = EncryptionFingerprintFactory.create(context, data.toString());
            return this;
        }

        public Builder encryptionFingerprint(EncryptionFingerprint fingerprint) {
            Objects.requireNonNull(fingerprint);
            this.fingerprint = fingerprint;
            return this;
        }

        public Builder encryptionFingerprint(byte[] fingerprint) {
            Objects.requireNonNull(fingerprint);
            this.fingerprint = new EncryptionFingerprint.Default(fingerprint);
            return this;
        }

        /**
         * Set the salt for the content key digest.
         * Content key is the key used in e.g. {@link SharedPreferences#getInt(String, int)}.
         * Salt should be 16 byte or longer.
         *
         * <p>
         * Only set if you know what you are doing.
         *
         * @param salt to set
         * @return builder
         */
        public Builder contentKeyDigest(byte[] salt) {
            return contentKeyDigest(new HkdfMessageDigest(salt, CONTENT_KEY_OUT_BYTE_LENGTH));
        }

        /**
         * The the out length of the key digest (the longer, the more storage is used during persistence)
         * Content key is the key used in e.g. {@link SharedPreferences#getInt(String, int)}.
         * Key out length should be 16 byte or longer.
         *
         * <p>
         * Only set if you know what you are doing.
         *
         * @param contentKeyOutLength to set
         * @return builder
         */
        public Builder contentKeyDigest(int contentKeyOutLength) {
            return contentKeyDigest(new HkdfMessageDigest(BuildConfig.PREF_SALT, contentKeyOutLength));
        }

        /**
         * Set a custom implemention of {@link StringMessageDigest}
         * Content key is the key used in e.g. {@link SharedPreferences#getInt(String, int)}.
         *
         * <p>
         * Only set if you know what you are doing.
         *
         * @param stringMessageDigest to set
         * @return builder
         */
        public Builder contentKeyDigest(StringMessageDigest stringMessageDigest) {
            this.stringMessageDigest = Objects.requireNonNull(stringMessageDigest);
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
        public Builder encryptionKeyStrength(@AuthenticatedEncryption.KeyStrength int keyStrength) {
            defaultConfig.keyStrength(keyStrength);
            return this;
        }

        /**
         * Set the security provider for most cryptographic primitives (symmetric encryption,
         * pbkdf2, ...). Per default the default provider is used and this should be fine in most
         * cases.
         * <p>
         * Only set if you know what you are doing.
         *
         * @param provider JCA provider
         * @return builder
         */
        public Builder securityProvider(Provider provider) {
            this.provider = provider;
            return this;
        }

        /**
         * Set your own implementation of {@link AuthenticatedEncryption}. Use this if setting
         * the security provider with {@link Armadillo.Builder#securityProvider(Provider)} is not enough
         * customization. With this a any symmetric encryption algorithm might be used.
         * <p>
         * Only set if you know what you are doing.
         *
         * @param authenticatedEncryption to be used by the shared preferences
         * @return builder
         */
        public Builder symmetricEncryption(AuthenticatedEncryption authenticatedEncryption) {
            defaultConfig.authenticatedEncryption(Objects.requireNonNull(authenticatedEncryption));
            return this;
        }

        /**
         * Set a different key derivation function for provided password. Per default {@link ArmadilloBcryptKeyStretcher}
         * is used. There is also a implementation PBKDF2 (see {@link PBKDF2KeyStretcher}. If you want
         * to use a different function (e.g. scrypt) set the implementation here.
         * <p>
         * If you want to disable the key stretching feature you might use {@link FastKeyStretcher} here.
         *
         * @param keyStretchingFunction to be used by the shared preferences
         * @return builder
         */
        public Builder keyStretchingFunction(KeyStretchingFunction keyStretchingFunction) {
            defaultConfig.keyStretchingFunction(Objects.requireNonNull(keyStretchingFunction));
            return this;
        }

        /**
         * Set your own data obfuscation implementation. Data obfuscation is used to disguise the
         * persistence data format. See {@link HkdfXorObfuscator} for the default obfuscation technique.
         * <p>
         * Only set if you know what you are doing.
         *
         * @param dataObfuscatorFactory that creates a obfuscator with given key
         * @return builder
         */
        public Builder dataObfuscatorFactory(DataObfuscator.Factory dataObfuscatorFactory) {
            defaultConfig.dataObfuscatorFactory(Objects.requireNonNull(dataObfuscatorFactory));
            return this;
        }

        /**
         * Provide your own {@link SecureRandom} implementation.
         * Per default a no-provider constructor is used for {@link SecureRandom} which
         * is the currently recommended way (https://tersesystems.com/blog/2015/12/17/the-right-way-to-use-securerandom/)
         * <p>
         * Only set if you know what you are doing.
         *
         * @param secureRandom implementation
         * @return builder
         */
        public Builder secureRandom(SecureRandom secureRandom) {
            Objects.requireNonNull(secureRandom);
            this.secureRandom = secureRandom;
            return this;
        }

        public Builder recoveryPolicy(boolean throwRuntimeException, boolean removeBrokenContent) {
            this.recoveryPolicy = new RecoveryPolicy.Default(throwRuntimeException, removeBrokenContent);
            return this;
        }

        public Builder recoveryPolicy(RecoveryPolicy recoveryPolicy) {
            Objects.requireNonNull(recoveryPolicy);
            this.recoveryPolicy = recoveryPolicy;
            return this;
        }

        /**
         * Provide a user password used for all of entries of the {@link SharedPreferences}.
         * <p>
         * The password is treated as weak and is therefore subject to be stretched by the provided key
         * derivation function with key stretching property (see {@link Builder#keyStretchingFunction(KeyStretchingFunction)}.
         * A side-effect is that putting or reading content is expensive and should not be done on the main thread.
         * <p>
         * A null password or zero length password will be treated as if no user-provided password was set.
         *
         * @param password provided by user
         * @return builder
         */
        public Builder password(@Nullable char[] password) {
            this.password = password == null || password.length == 0 ? null : password;
            return this;
        }

        /**
         * Per default the crypto/data format version is '0', but if the behavior is changed by e.g.
         * setting a different key-stretching function or contentKey digest, a custom crypto protocol
         * version can be set, to be able to migrate the data.
         * <p>
         * The protocol version will be used as additional associated data with the authenticated encryption.
         *
         * @param version to persist with the data
         * @return builder
         */
        public Builder cryptoProtocolVersion(int version) {
            defaultConfig.protocolVersion(version);
            return this;
        }

        /**
         * Compresses the content with Gzip before encrypting and writing it to shared preference. This only makes
         * sense if bigger structural data is persisted like long xml or json.
         *
         * @return builder
         */
        public Builder compress() {
            return compress(new GzipCompressor());
        }

        /**
         * Compresses the content with given compressor before encrypting and writing it to shared preference.
         *
         * @param compressor to set
         * @return builder
         */
        public Builder compress(Compressor compressor) {
            defaultConfig.compressor(compressor);
            return this;
        }

        /**
         * Add new {@link EncryptionProtocolConfig} to be added to the supported decryption-config
         * list. That means, if you have encrypted data with an older encryption config you may add
         * it here to be able to <strong>decrypt</strong> it again. These configs are however never
         * used for <strong>encryption</strong>.
         * <p>
         * To match configs {@link EncryptionProtocolConfig#protocolVersion} is used, therefore if
         * you add a config here it must match the persisted protocolVersion (Armadillo default is
         * {@link #DEFAULT_PROTOCOL_VERSION})
         * <p>
         * This may be used for migration of encryption protocols.
         *
         * @param config to be added to the list
         * @return builder
         */
        public Builder addAdditionalDecryptionProtocolConfig(EncryptionProtocolConfig config) {
            additionalDecryptionConfigs.add(config);
            return this;
        }

        /**
         * Clear additionalDecryptionConfigs list.
         * See also {@link #addAdditionalDecryptionProtocolConfig(EncryptionProtocolConfig)}.
         *
         * @return builder
         */
        public Builder clearAdditionalDecryptionProtocolConfigs() {
            additionalDecryptionConfigs.clear();
            return this;
        }

        /**
         * Manually enable kitkatSupport. Unfortunately Android SDK 19 (KITKAT) does not fully
         * support AES GCM mode. Therefore a backwards compatible implementation of AES
         * (see {@link AesCbcEncryption}) which uses CBC + Encrypt-then-mac which should have
         * a similar security strength.
         * <p>
         * The backwards compatible implementation will <strong>only</strong> be used if
         * {@link Build.VERSION#SDK_INT} is lower or equal to 19, the default version otherwise.
         * Additionally this implementation will be added to the additionalDecryptionConfigs so you
         * can still decrypt the old content after upgrading to lollipop and above (uses protocol-version
         * {@link Armadillo#KITKAT_PROTOCOL_VERSION} to mark.
         *
         * @param enable kitkat support
         * @return builder
         */
        public Builder enableKitKatSupport(boolean enable) {
            enableKitKatSupport = enable;
            return this;
        }

        /**
         * Build a {@link SharedPreferences} instance
         *
         * @return shared preference with given properties
         */
        public ArmadilloSharedPreferences build() {
            if (fingerprint == null) {
                throw new IllegalArgumentException("No encryption fingerprint is set - see encryptionFingerprint() methods");
            }

            EncryptionProtocolConfig config = defaultConfig.build();

            if (enableKitKatSupport) {
                if (config.authenticatedEncryption != null) {
                    throw new IllegalStateException("enabling kitkat support will prevent using custom encryption implementation");
                }

                @SuppressWarnings("deprecation")
                EncryptionProtocolConfig kitkatSupportConfig = EncryptionProtocolConfig.newBuilder(config)
                        .authenticatedEncryption(new AesCbcEncryption(secureRandom, provider))
                        .protocolVersion(KITKAT_PROTOCOL_VERSION)
                        .build();

                additionalDecryptionConfigs.add(kitkatSupportConfig);

                // set current encryption config to kitkat support if on kitkat device
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
                    config = kitkatSupportConfig;
                }
            }

            if (config.authenticatedEncryption == null) {
                config = EncryptionProtocolConfig.newBuilder(config)
                        .authenticatedEncryption(new AesGcmEncryption(secureRandom, provider)).build();
            }

            EncryptionProtocol.Factory factory = new DefaultEncryptionProtocol.Factory(config,
                    fingerprint, stringMessageDigest, secureRandom, additionalDecryptionConfigs);

            checkKitKatSupport(config.authenticatedEncryption);

            if (sharedPreferences != null) {
                return new SecureSharedPreferences(sharedPreferences, factory, recoveryPolicy, password);
            } else {
                return new SecureSharedPreferences(context, prefName, factory, recoveryPolicy, password);
            }
        }

        private void checkKitKatSupport(AuthenticatedEncryption authenticatedEncryption) {
            if (Build.VERSION.SDK_INT == Build.VERSION_CODES.KITKAT &&
                    authenticatedEncryption.getClass().equals(AesGcmEncryption.class)) {
                throw new UnsupportedOperationException("aes gcm is not supported with KitKat, add support " +
                        "manually with Armadillo.Builder.enableKitKatSupport()");
            }
        }
    }
}
