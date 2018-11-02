package at.favre.lib.armadillo;

import android.content.Context;
import android.content.SharedPreferences;
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
        private boolean enableDerivedPasswordCache = false;
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

        public Builder contentKeyDigest(byte[] salt) {
            return contentKeyDigest(new HkdfMessageDigest(salt, CONTENT_KEY_OUT_BYTE_LENGTH));
        }

        public Builder contentKeyDigest(int contentKeyOutLength) {
            return contentKeyDigest(new HkdfMessageDigest(BuildConfig.PREF_SALT, contentKeyOutLength));
        }

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
            this.keyStrength = keyStrength;
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
         * <p>
         * Only set if you know what you are doing.
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
         *
         * @param version to persist with the data
         * @return builder
         */
        public Builder cryptoProtocolVersion(int version) {
            this.cryptoProtocolVersion = version;
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
         * <li>Slightly reduces security strenght, since the stretched bytes are kept in memory for longer</li>
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
                keyStretchingFunction, dataObfuscatorFactory, secureRandom, enableDerivedPasswordCache, compressor);

            if (sharedPreferences != null) {
                return new SecureSharedPreferences(sharedPreferences, factory, recoveryPolicy, password, supportVerifyPassword);
            } else {
                return new SecureSharedPreferences(context, prefName, factory, recoveryPolicy, password, supportVerifyPassword);
            }
        }
    }
}
