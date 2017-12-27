package at.favre.lib.armadillo;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.Nullable;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.Objects;

import at.favre.lib.bytes.Bytes;

/**
 * @since 26.12.2017
 */

public final class Armadillo {
    public static final int CONTENT_KEY_OUT_BYTE_LENGTH = 20;

    public static Builder create(SharedPreferences sharedPreferences) {
        return new Builder(sharedPreferences);
    }

    public static Builder create(Context context, String prefName) {
        return new Builder(context, prefName);
    }

    public final static class Builder {

        private final SharedPreferences sharedPreferences;
        private final Context context;
        private final String prefName;

        private EncryptionFingerprint fingerprint;
        private StringMessageDigest stringMessageDigest = new HkdfMessageDigest(BuildConfig.PREF_SALT, CONTENT_KEY_OUT_BYTE_LENGTH);
        @AuthenticatedEncryption.KeyStrength
        private int keyStrength = AuthenticatedEncryption.STRENGTH_HIGH;
        private AuthenticatedEncryption authenticatedEncryption;
        private KeyStretchingFunction keyStretchingFunction = new BcryptKeyStretcher();
        private DataObfuscator.Factory dataObfuscatorFactory = new HkdfXorObfuscator.Factory();
        private SecureRandom secureRandom = new SecureRandom();
        private RecoveryPolicy recoveryPolicy = new RecoveryPolicy.Default(false, true);
        private char[] password;
        private Provider provider;

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
         * kinds of attacks you wouldn't use this lib anyway)
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
         * <p>
         * Only set if you know what you are doing.
         *
         * @param provider JCA provider
         * @return builder
         */
        public Builder securityProvider(Provider provider) {
            Objects.requireNonNull(provider);
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
         * Set a different key derivation function for provided password. Per default {@link BcryptKeyStretcher}
         * is used. There is also a implementation PBKDF2 (see {@link PBKDF2KeyStretcher}. If you want
         * to use a different function (e.g. scrypt) set the implementation here.
         *
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
         * Provide a user password used for all of entries of the {@link SharedPreferences}.
         * <p>
         * The password is treated as weak and is therefore subject to be stretched by the provided key
         * derivation function with key stretching property (see {@link Builder#keyStretchingFunction(KeyStretchingFunction)}.
         * A side-effect is that putting or reading content is expensive and should not be done on the main thread.
         *
         * @param password provided by user
         * @return builder
         */
        public Builder password(char[] password) {
            this.password = password;
            return this;
        }

        /**
         * Build a {@link SharedPreferences} instance
         *
         * @return shared preference with given properties
         */
        public SharedPreferences build() {
            if (fingerprint == null) {
                throw new IllegalArgumentException("No encryption fingerprint is set - see encryptionFingerprint() methods");
            }

            if (authenticatedEncryption == null) {
                authenticatedEncryption = new AesGcmEncryption(secureRandom, provider);
            }

            EncryptionProtocol.Factory factory = new DefaultEncryptionProtocol.Factory(fingerprint, stringMessageDigest, authenticatedEncryption, keyStrength,
                    keyStretchingFunction, dataObfuscatorFactory, secureRandom);

            if (sharedPreferences != null) {
                return new SecureSharedPreferences(sharedPreferences, factory, recoveryPolicy, password);
            } else {
                return new SecureSharedPreferences(context, prefName, factory, recoveryPolicy, password);
            }
        }
    }
}
