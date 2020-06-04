package at.favre.lib.armadillo;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import androidx.annotation.Nullable;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
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
    static Logger logger = new DefaultLogger();

    private Armadillo() {
    }

    /**
     * Create a new instance of the builder with a custom implementation of shared preference.
     * If you want to omit the default behaviour how Armadillo sets up a {@link SharedPreferences}
     * instance, use this create. This is also useful for testing purposes.
     * <p>
     * Note that this is a more advanced feature and usually you want
     * the default implementation with {@link #create(Context, String)}.
     *
     * @param sharedPreferences to use as backing persistence layer
     * @return builder
     */
    public static Builder create(SharedPreferences sharedPreferences) {
        return new Builder(sharedPreferences);
    }

    /**
     * Create a new builder for Armadillo. Will internally create a {@link SharedPreferences} from
     * given context. Pass the preference name (think of database name), which is unique to your
     * persistence layer (e.g. if you create with the same preference name you will get the old
     * stored values).
     * <p>
     * This name will be used to derive the file name used to store the shared preference xml on disk
     * (read: it will be hashed, not directly used).
     *
     * @param context        to get shared preference and other Android OS specific data
     * @param preferenceName to identify the persistence store
     * @return builder
     */
    public static Builder create(Context context, String preferenceName) {
        return new Builder(context, preferenceName);
    }

    /**
     * Logs by default are sent to {@link Log}. Passing null as a here will turn off logging.
     *
     * @param logger A {@link Logger}
     */
    public static void setLogger(@Nullable final Logger logger) {
        if (logger == null) {
            Armadillo.logger = new NoOpLogger();
        } else {
            Armadillo.logger = logger;
        }
    }

    static void log(int logLevel, String tag, String message, Object... args) {
        Armadillo.logger.log(logLevel, tag, message, args)
    }

    /**
     * Builder pattern for creating the configuration for an {@link ArmadilloSharedPreferences} instance
     */
    public static final class Builder {

        private final SharedPreferences sharedPreferences;
        private final Context context;
        private final String prefName;

        private EncryptionFingerprint fingerprint;
        private StringMessageDigest stringMessageDigest = new HkdfMessageDigest(BuildConfig.PREF_SALT, CONTENT_KEY_OUT_BYTE_LENGTH);
        private EncryptionProtocolConfig.Builder defaultConfig = EncryptionProtocolConfig.newDefaultConfig();
        private List<EncryptionProtocolConfig> additionalDecryptionConfigs = new ArrayList<>(2);
        private SecureRandom secureRandom = new SecureRandom();
        private RecoveryPolicy recoveryPolicy = new SimpleRecoveryPolicy.Default(true, false);
        private char[] password;
        private boolean supportVerifyPassword = false;
        private Provider provider;
        private boolean enableDerivedPasswordCache = false;
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

        /**
         * The encryption fingerprint is in important security measure. When no user password is
         * provided, it is the most important source of entropy to derive the key for the encryption.
         * <p>
         * Set the default fingerprint using sources explained in {@link EncryptionFingerprintFactory}.
         *
         * @param context used to gather sources from the Android OS
         * @return builder
         */
        public Builder encryptionFingerprint(Context context) {
            return encryptionFingerprint(context, (String[]) null);
        }

        /**
         * The encryption fingerprint is in important security measure. When no user password is
         * provided, it is the most important source of entropy to derive the key for the encryption.
         * <p>
         * Set the default fingerprint using sources explained in {@link EncryptionFingerprintFactory}
         * with addtional custom data. Setting this is <strong>highly recommended</strong> as it makes
         * it more difficult for an attacker calculate the key the more random the input is.
         * <p>
         * See the README.md for explainating on what to use as additionalData.
         *
         * @param context        used to gather sources from the Android OS
         * @param additionalData provided additional custom data
         * @return builder
         */
        public Builder encryptionFingerprint(Context context, byte[] additionalData) {
            return encryptionFingerprint(context, Bytes.wrap(additionalData).encodeBase64());
        }

        /**
         * The encryption fingerprint is in important security measure. When no user password is
         * provided, it is the most important source of entropy to derive the key for the encryption.
         * <p>
         * Set the default fingerprint using sources explained in {@link EncryptionFingerprintFactory}
         * with addtional custom data. Setting this is <strong>highly recommended</strong> as it makes
         * it more difficult for an attacker calculate the key the more random the input is.
         * <p>
         * This is the same as {@link #encryptionFingerprint(Context, byte[])} but accepts strings
         * instead of a byte array.
         * <p>
         * See the README.md for explainating on what to use as additionalData.
         *
         * @param context        used to gather sources from the Android OS
         * @param additionalData provided additional custom data
         * @return builder
         */
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

        /**
         * The encryption fingerprint is in important security measure. When no user password is
         * provided, it is the most important source of entropy to derive the key for the encryption.
         * <p>
         * Provide a fully custom fingerprint implementation (or instance). Use this if you don't
         * agree with the default implementation.
         * <hr />
         * <strong>Note:</strong> <em>Only set if you know what you are doing.</em>
         *
         * @param fingerprint fully custom instance
         * @return builder
         */
        public Builder encryptionFingerprint(EncryptionFingerprint fingerprint) {
            Objects.requireNonNull(fingerprint);
            this.fingerprint = fingerprint;
            return this;
        }

        /**
         * The encryption fingerprint is in important security measure. When no user password is
         * provided, it is the most important source of entropy to derive the key for the encryption.
         * <p>
         * Provide a fully custom fingerprint byte array. Use this if you don't
         * agree with the default implementation.
         * <hr />
         * <strong>Note:</strong> <em>Only set if you know what you are doing.</em>
         *
         * @param fingerprint fully custom byte array containing the fingerprint
         * @return builder
         */
        public Builder encryptionFingerprint(byte[] fingerprint) {
            Objects.requireNonNull(fingerprint);
            this.fingerprint = new EncryptionFingerprint.Default(fingerprint);
            return this;
        }

        /**
         * The content key digest is responsible for hashing the key in the key-value pair of
         * a shared preference. E.g. if the key is "name" and the value "Bob", the key "name" will
         * be hashed before it is persisted to disk.
         * <p>
         * This method will alter the salt used for that hash. Setting this is highly recommended, since
         * it will change the default hashes of the key (so that somebody else's "name" key, won't
         * hash to the exact same output). Recommended value: use the AndroidID, as it will be different
         * on every app install from SDK 26+. See {@link Settings.Secure#ANDROID_ID}.
         * <p>
         * Note that changing the salt will make old data inaccessible, since the key won't match
         * anymore.
         *
         * @param salt to be used for content key hash (should be > 16 byte)
         * @return builder
         */
        public Builder contentKeyDigest(byte[] salt) {
            return contentKeyDigest(new HkdfMessageDigest(salt, CONTENT_KEY_OUT_BYTE_LENGTH));
        }

        /**
         * The content key digest is responsible for hashing the key in the key-value pair of
         * a shared preference. E.g. if the key is "name" and the value "Bob", the key "name" will
         * be hashed before it is persisted to disk.
         * <p>
         * This is a more advanced setting. Per default a hash will be {@link #CONTENT_KEY_OUT_BYTE_LENGTH}
         * bytes long. If you think that is too long (wasting space) or too small (not enough entropy)
         * modify the length with this config.
         * <hr />
         * <strong>Note:</strong> <em>Only set if you know what you are doing.</em>
         *
         * @param contentKeyOutLength to be used for content key hash
         * @return builder
         */
        public Builder contentKeyDigest(int contentKeyOutLength) {
            return contentKeyDigest(new HkdfMessageDigest(BuildConfig.PREF_SALT, contentKeyOutLength));
        }

        /**
         * The content key digest is responsible for hashing the key in the key-value pair of
         * a shared preference. E.g. if the key is "name" and the value "Bob", the key "name" will
         * be hashed before it is persisted to disk.
         * <p>
         * Use this to set a fully custom implementation of the digest.
         * <hr />
         * <strong>Note:</strong> <em>Only set if you know what you are doing.</em>
         *
         * @param stringMessageDigest custom implementation
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
         * kinds of attacks you probably require higher degrees af protection).
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
         * <hr />
         * <strong>Note:</strong> <em>Only set if you know what you are doing.</em>
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
         * <hr />
         * <strong>Note:</strong> <em>Only set if you know what you are doing.</em>
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
         * <hr />
         * <strong>Note:</strong> <em>Only set if you know what you are doing.</em>
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
         * <hr />
         * <strong>Note:</strong> <em>Only set if you know what you are doing.</em>
         *
         * @param secureRandom implementation
         * @return builder
         */
        public Builder secureRandom(SecureRandom secureRandom) {
            Objects.requireNonNull(secureRandom);
            this.secureRandom = secureRandom;
            return this;
        }

        /**
         * The recovery policy defines how to behave when a value cannot be decrypted.
         *
         * @param throwRuntimeException if a exception will be thrown (out of the '.get*()' method)
         * @param removeBrokenContent   if the content should be automatically be removed
         * @return builder
         */
        public Builder recoveryPolicy(boolean throwRuntimeException, boolean removeBrokenContent) {
            this.recoveryPolicy = new SimpleRecoveryPolicy.Default(throwRuntimeException, removeBrokenContent);
            return this;
        }

        /**
         * The recovery policy defines how to behave when a value cannot be decrypted. Use this
         * if you want a more fine-grained strategy. This is not meant for migration however.
         *
         * @param recoveryPolicy a custom implementation
         * @return builder
         */
        public Builder recoveryPolicy(RecoveryPolicy recoveryPolicy) {
            this.recoveryPolicy = Objects.requireNonNull(recoveryPolicy);
            return this;
        }

        /**
         * Provide a user password used for encrypting all of values of the {@link SharedPreferences}.
         * <p>
         * The password is treated as weak and is therefore subject to be stretched by the provided key
         * derivation function with key stretching property (see {@link Builder#keyStretchingFunction(KeyStretchingFunction)}.
         * A side-effect is that putting or reading content is expensive and should not be done on the main thread.
         * <p>
         * A null password or zero length password will be treated as if no user-provided password was set.
         * <p>
         * If you want to be able to verify the password, set {@link Builder#supportVerifyPassword(boolean)}
         * to true and use {@link ArmadilloSharedPreferences#isValidPassword()} to verify.
         * By default, support verify password is disabled.
         *
         * @param password provided by user
         * @return builder
         */
        public Builder password(@Nullable char[] password) {
            this.password = password == null || password.length == 0 ? null : password;
            return this;
        }

        /**
         * Enabling support verify password allows you to use {@link ArmadilloSharedPreferences#isValidPassword()}
         * to verify the validity of the user-provided password used to initialise Armadillo.
         * In order to verify the password, a known value is stored encrypted with the password the
         * first time that Armadillo is initialised. When {@link ArmadilloSharedPreferences#isValidPassword()}
         * is called, it tries to decrypt this value and compares it to the original value. If the values
         * match the validation succeeds, otherwise, it fails.
         * By default, support verify password is disabled.
         *
         * @param supported true to supported password verification, false otherwise
         * @return builder
         */
        public Builder supportVerifyPassword(boolean supported) {
            this.supportVerifyPassword = supported;
            return this;
        }

        /**
         * Per default the crypto/data format version is '0', but if the behavior is changed by e.g.
         * setting a different key-stretching function or contentKey digest, a custom crypto protocol
         * version can be set, to be able to migrate the data.
         * <p>
         * The protocol version will be used as additional associated data with the authenticated encryption.
         * <hr />
         * <strong>Note:</strong> <em>Only set if you know what you are doing.</em>
         *
         * @param version to persist with the data
         * @return builder
         */
        public Builder cryptoProtocolVersion(int version) {
            defaultConfig.protocolVersion(version);
            return this;
        }

        /**
         * Per default every put and get operation, when using a user provided password, requires the
         * full expensive key derivation function (KDF) to derive the key. This can add up to multiple
         * seconds if you get/put multiple values consecutively. Default is false.
         * <p>
         * To make get* calls faster, you can enable this cache, which caches the <em>derived</em>
         * password. This will not speed up put* operations since every time a new salt will be created
         * making it impossible to cache. The disadvantage is that the derived password stays in cache
         * , therefor in memory for way longer, making it easier to read when the device is used with
         * instrumentation tool like FRIDA (this is a more specific attack, since when the attacker has
         * full access to the device, there is not much you can do).
         * <p>
         *
         * <strong>Summary</strong>
         * <ul>
         * <li>Improves performance of consecutive get calls when using expensive key stretching function and user password</li>
         * <li>Slightly reduces security strength, since the stretched bytes are kept in memory for longer</li>
         * </ul>
         * <p>
         * See {@link DerivedPasswordCache} for details of the implementation.
         *
         * @param enable caching
         * @return builder
         */
        public Builder enableDerivedPasswordCache(boolean enable) {
            enableDerivedPasswordCache = enable;
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
                    fingerprint, stringMessageDigest, secureRandom, enableDerivedPasswordCache, Collections.unmodifiableList(additionalDecryptionConfigs));

            checkKitKatSupport(config.authenticatedEncryption);

            if (sharedPreferences != null) {
                return new SecureSharedPreferences(sharedPreferences, factory, recoveryPolicy, password, supportVerifyPassword);
            } else {
                return new SecureSharedPreferences(context, prefName, factory, recoveryPolicy, password, supportVerifyPassword);
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

    public interface Logger {
        void log(int logLevel, String tag, String message, Object... args);
    }

    private static class DefaultLogger implements Logger {

        @Override
        public void log(int logLevel, String tag, String message, Object... args) {
            final String logMessage = String.format(message, args);
            Log.println(logLevel, tag, logMessage);
        }
    }

    private static class NoOpLogger implements Logger {
        @Override
        public void log(int logLevel, String tag, String message, Object... args) {
            // do nothing.
        }
    }
}
