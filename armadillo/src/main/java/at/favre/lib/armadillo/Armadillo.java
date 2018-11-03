package at.favre.lib.armadillo;

import android.content.Context;
import android.content.SharedPreferences;
import android.provider.Settings;
import android.support.annotation.Nullable;

import java.security.Provider;
import java.security.SecureRandom;
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
     * Builder pattern for creating the configuration for an {@link ArmadilloSharedPreferences} instance
     */
    public static final class Builder {

        private final SharedPreferences sharedPreferences;
        private final Context context;
        private final String prefName;

        private EncryptionFingerprint fingerprint;
        private StringMessageDigest stringMessageDigest = new HkdfMessageDigest(BuildConfig.PREF_SALT, CONTENT_KEY_OUT_BYTE_LENGTH);
        @AuthenticatedEncryption.KeyStrength
        private int keyStrength = AuthenticatedEncryption.STRENGTH_HIGH;
        private AuthenticatedEncryption authenticatedEncryption;
        private KeyStretchingFunction keyStretchingFunction = new ArmadilloBcryptKeyStretcher();
        private DataObfuscator.Factory dataObfuscatorFactory = new HkdfXorObfuscator.Factory();
        private SecureRandom secureRandom = new SecureRandom();
        private RecoveryPolicy recoveryPolicy = new RecoveryPolicy.Default(true, false);
        private char[] password;
        private boolean supportVerifyPassword = false;
        private Provider provider;
        private int cryptoProtocolVersion = 0;
        private Compressor compressor = new DisabledCompressor();

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
         *
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
         *
         * Set the default fingerprint using sources explained in {@link EncryptionFingerprintFactory
         * with addtional custom data. Setting this is <strong>highly recommended</strong> as it makes
         * it more difficult for an attacker calculate the key the more random the input is.
         *
         * See the README.md for explainating on what to use as additionalData.
         *
         * @param context used to gather sources from the Android OS
         * @param additionalData provided additional custom data
         * @return builder
         */
        public Builder encryptionFingerprint(Context context, byte[] additionalData) {
            return encryptionFingerprint(context, Bytes.wrap(additionalData).encodeBase64());
        }

        /**
         * The encryption fingerprint is in important security measure. When no user password is
         * provided, it is the most important source of entropy to derive the key for the encryption.
         *
         * Set the default fingerprint using sources explained in {@link EncryptionFingerprintFactory
         * with addtional custom data. Setting this is <strong>highly recommended</strong> as it makes
         * it more difficult for an attacker calculate the key the more random the input is.
         *
         * This is the same as {@link #encryptionFingerprint(Context, byte[])} but accepts strings
         * instead of a byte array.
         *
         * See the README.md for explainating on what to use as additionalData.
         *
         * @param context used to gather sources from the Android OS
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
         *
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
         *
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
         *
         * This method will alter the salt used for that hash. Setting this is highly recommended, since
         * it will change the default hashes of the key (so that somebody else's "name" key, won't
         * hash to the exact same output). Recommended value: use the AndroidID, as it will be different
         * on every app install from SDK 26+. See {@link Settings.Secure#ANDROID_ID}.
         *
         * Note that changing the salt will make old data inaccessible, since the key won't match
         * anymore.
         *
         * @param salt to be used for content key hash
         * @return builder
         */
        public Builder contentKeyDigest(byte[] salt) {
            return contentKeyDigest(new HkdfMessageDigest(salt, CONTENT_KEY_OUT_BYTE_LENGTH));
        }

        /**
         * The content key digest is responsible for hashing the key in the key-value pair of
         * a shared preference. E.g. if the key is "name" and the value "Bob", the key "name" will
         * be hashed before it is persisted to disk.
         *
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
         *
         * Use this to set a fully custom implementation of the digest.
         * <hr />
         * <strong>Note:</strong> <em>Only set if you know what you are doing.</em>
         *
         * @param stringMessageDigest custom implementation
         * @return builder
         */
        public Builder contentKeyDigest(StringMessageDigest stringMessageDigest) {
            Objects.requireNonNull(stringMessageDigest);
            this.stringMessageDigest = stringMessageDigest;
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
         * kinds of attacks you wouldn't use this lib anyway).
         *
         * @param keyStrength HIGH (default) or VERY HIGH
         * @return builder
         */
        public Builder encryptionKeyStrength(@AuthenticatedEncryption.KeyStrength int keyStrength) {
            Objects.requireNonNull(keyStrength);
            this.keyStrength = keyStrength;
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
            Objects.requireNonNull(authenticatedEncryption);
            this.authenticatedEncryption = authenticatedEncryption;
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
            Objects.requireNonNull(keyStretchingFunction);
            this.keyStretchingFunction = keyStretchingFunction;
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
            Objects.requireNonNull(dataObfuscatorFactory);
            this.dataObfuscatorFactory = dataObfuscatorFactory;
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
            this.cryptoProtocolVersion = version;
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
         * @return builder
         */
        public Builder compress(Compressor compressor) {
            this.compressor = compressor;
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

            if (authenticatedEncryption == null) {
                authenticatedEncryption = new AesGcmEncryption(secureRandom, provider);
            }

            EncryptionProtocol.Factory factory = new DefaultEncryptionProtocol.Factory(cryptoProtocolVersion, fingerprint, stringMessageDigest, authenticatedEncryption, keyStrength,
                keyStretchingFunction, dataObfuscatorFactory, secureRandom, compressor);

            if (sharedPreferences != null) {
                return new SecureSharedPreferences(sharedPreferences, factory, recoveryPolicy, password, supportVerifyPassword);
            } else {
                return new SecureSharedPreferences(context, prefName, factory, recoveryPolicy, password, supportVerifyPassword);
            }
        }
    }
}
