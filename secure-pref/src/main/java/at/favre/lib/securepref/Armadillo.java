package at.favre.lib.securepref;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.Nullable;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.Objects;

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
        private ContentKeyDigest contentKeyDigest = new HkdfKeyDigest(BuildConfig.PREF_SALT, CONTENT_KEY_OUT_BYTE_LENGTH);
        @SymmetricEncryption.KeyStrength
        private int keyStrength = SymmetricEncryption.STRENGTH_HIGH;
        private SymmetricEncryption symmetricEncryption;
        private KeyStretchingFunction keyStretchingFunction = new PBKDF2KeyStretcher();
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
            return encryptionFingerprint(context, null);
        }

        public Builder encryptionFingerprint(Context context, @Nullable String additionalData) {
            Objects.requireNonNull(context);
            this.fingerprint = EncryptionFingerprintFactory.create(context, additionalData);
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
            return contentKeyDigest(new HkdfKeyDigest(salt, CONTENT_KEY_OUT_BYTE_LENGTH));
        }

        public Builder contentKeyDigest(int contentKeyOutLength) {
            return contentKeyDigest(new HkdfKeyDigest(BuildConfig.PREF_SALT, contentKeyOutLength));
        }

        public Builder contentKeyDigest(ContentKeyDigest contentKeyDigest) {
            Objects.requireNonNull(contentKeyDigest);
            this.contentKeyDigest = contentKeyDigest;
            return this;
        }

        public Builder encryptionKeyStrength(@SymmetricEncryption.KeyStrength int keyStrength) {
            Objects.requireNonNull(keyStrength);
            this.keyStrength = keyStrength;
            return this;
        }

        public Builder securityProvider(Provider provider) {
            Objects.requireNonNull(provider);
            this.provider = provider;
            return this;
        }

        public Builder symmetricEncryption(SymmetricEncryption symmetricEncryption) {
            Objects.requireNonNull(symmetricEncryption);
            this.symmetricEncryption = symmetricEncryption;
            return this;
        }

        public Builder keyStretchingFunction(KeyStretchingFunction keyStretchingFunction) {
            Objects.requireNonNull(keyStretchingFunction);
            this.keyStretchingFunction = keyStretchingFunction;
            return this;
        }

        public Builder dataObfuscatorFactory(DataObfuscator.Factory dataObfuscatorFactory) {
            Objects.requireNonNull(dataObfuscatorFactory);
            this.dataObfuscatorFactory = dataObfuscatorFactory;
            return this;
        }

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

        public Builder password(char[] password) {
            this.password = password;
            return this;
        }

        public SharedPreferences build() {
            if (fingerprint == null) {
                throw new IllegalArgumentException("No encryption fingerprint is set - see encryptionFingerprint() methods");
            }

            if (symmetricEncryption == null) {
                symmetricEncryption = new AesGcmEncryption(secureRandom, provider);
            }

            EncryptionProtocol.Factory factory = new DefaultEncryptionProtocol.Factory(fingerprint, contentKeyDigest, symmetricEncryption, keyStrength,
                    keyStretchingFunction, dataObfuscatorFactory, secureRandom);

            if (sharedPreferences != null) {
                return new SecureSharedPreferences(sharedPreferences, factory, recoveryPolicy, password);
            } else {
                return new SecureSharedPreferences(context, prefName, factory, recoveryPolicy, password);
            }
        }
    }
}
