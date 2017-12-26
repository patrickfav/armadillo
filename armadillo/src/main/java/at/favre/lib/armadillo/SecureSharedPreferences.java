package at.favre.lib.armadillo;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import at.favre.lib.bytes.Bytes;

/**
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

public class SecureSharedPreferences implements SharedPreferences {

    private final static String KEY_RANDOM = "at.favre.lib.securepref.KEY_RANDOM";

    private final SharedPreferences sharedPreferences;
    private final EncryptionProtocol encryptionProtocol;
    private final RecoveryPolicy recoveryPolicy;
    private final char[] password;

    public SecureSharedPreferences(Context context, String preferenceName, EncryptionProtocol.Factory encryptionProtocol, char[] password) {
        this(context, preferenceName, encryptionProtocol, new RecoveryPolicy.Default(false, true), password);
    }

    public SecureSharedPreferences(Context context, String preferenceName, EncryptionProtocol.Factory encryptionProtocol, RecoveryPolicy recoveryPolicy, char[] password) {
        this(context.getSharedPreferences(encryptionProtocol.getContentKeyDigest().derive(preferenceName, "prefName"), Context.MODE_PRIVATE),
                encryptionProtocol, recoveryPolicy, password);
    }

    public SecureSharedPreferences(SharedPreferences sharedPreferences, EncryptionProtocol.Factory encryptionProtocolFactory,
                                   RecoveryPolicy recoveryPolicy, char[] password) {
        this.sharedPreferences = sharedPreferences;
        this.recoveryPolicy = recoveryPolicy;
        this.password = password;
        this.encryptionProtocol = encryptionProtocolFactory.create(
                getPreferencesRandom(
                        encryptionProtocolFactory.getContentKeyDigest(),
                        encryptionProtocolFactory.createDataObfuscator(),
                        encryptionProtocolFactory.getSecureRandom()));
    }

    private byte[] getPreferencesRandom(ContentKeyDigest contentKeyDigest, DataObfuscator dataObfuscator, SecureRandom secureRandom) {
        final String keyHash = contentKeyDigest.derive(KEY_RANDOM, "prefName");
        String base64Random = sharedPreferences.getString(keyHash, null);
        byte[] outBytes;
        if (base64Random == null) {
            byte[] rndBytes = Bytes.random(32, secureRandom).array();
            dataObfuscator.obfuscate(rndBytes);
            sharedPreferences.edit().putString(keyHash, Bytes.wrap(rndBytes).encodeBase64()).apply();
            outBytes = rndBytes;
        } else {
            byte[] obfuscatedRandom = Bytes.parseBase64(base64Random).array();
            dataObfuscator.deobfuscate(obfuscatedRandom);
            outBytes = obfuscatedRandom;
        }
        return outBytes;
    }

    /**
     * This will get all handled keys from the store.
     * It will NOT decrypt any content.
     *
     * @return map with only the keys and null as value
     */
    @Override
    public Map<String, String> getAll() {
        final Map<String, ?> encryptedMap = sharedPreferences.getAll();
        final Map<String, String> keyOnlyMap = new HashMap<>(encryptedMap.size());
        for (String key : encryptedMap.keySet()) {
            keyOnlyMap.put(key, null);
        }
        return keyOnlyMap;
    }

    @Override
    public String getString(String key, String defaultValue) {
        final String keyHash = encryptionProtocol.deriveContentKey(key);
        final String encryptedValue = sharedPreferences.getString(keyHash, null);
        if (encryptedValue == null) {
            return defaultValue;
        }

        byte[] bytes = decrypt(keyHash, encryptedValue);
        if (bytes == null) {
            return defaultValue;
        }
        return Bytes.from(bytes).encodeUtf8();
    }

    @Override
    public Set<String> getStringSet(String key, Set<String> defaultValues) {
        final String keyHash = encryptionProtocol.deriveContentKey(key);
        final Set<String> encryptedSet = sharedPreferences.getStringSet(keyHash, null);
        if (encryptedSet == null) {
            return defaultValues;
        }

        final Set<String> decryptedSet = new HashSet<>(encryptedSet.size());

        for (String encryptedValue : encryptedSet) {
            byte[] bytes = decrypt(keyHash, encryptedValue);
            if (bytes == null) {
                return decryptedSet;
            }
            decryptedSet.add(Bytes.from(bytes).encodeUtf8());
        }
        return decryptedSet;
    }

    @Override
    public int getInt(String key, int defaultValue) {
        final String keyHash = encryptionProtocol.deriveContentKey(key);
        final String encryptedValue = sharedPreferences.getString(keyHash, null);
        if (encryptedValue == null) {
            return defaultValue;
        }

        byte[] bytes = decrypt(keyHash, encryptedValue);
        if (bytes == null) {
            return defaultValue;
        }
        return Bytes.from(bytes).toInt();
    }

    @Override
    public long getLong(String key, long defaultValue) {
        final String keyHash = encryptionProtocol.deriveContentKey(key);
        final String encryptedValue = sharedPreferences.getString(keyHash, null);
        if (encryptedValue == null) {
            return defaultValue;
        }

        byte[] bytes = decrypt(keyHash, encryptedValue);
        if (bytes == null) {
            return defaultValue;
        }
        return Bytes.from(bytes).toLong();
    }

    @Override
    public float getFloat(String key, float defaultValue) {
        final String keyHash = encryptionProtocol.deriveContentKey(key);
        final String encryptedValue = sharedPreferences.getString(keyHash, null);
        if (encryptedValue == null) {
            return defaultValue;
        }

        byte[] bytes = decrypt(keyHash, encryptedValue);
        if (bytes == null) {
            return defaultValue;
        }
        return Bytes.from(bytes).toFloat();
    }

    @Override
    public boolean getBoolean(String key, boolean defaultValue) {
        final String keyHash = encryptionProtocol.deriveContentKey(key);
        final String encryptedValue = sharedPreferences.getString(keyHash, null);
        if (encryptedValue == null) {
            return defaultValue;
        }

        byte[] bytes = decrypt(keyHash, encryptedValue);
        if (bytes == null) {
            return defaultValue;
        }
        return bytes[0] != 0;
    }

    @Override
    public boolean contains(String key) {
        return sharedPreferences.contains(encryptionProtocol.deriveContentKey(key));
    }

    @Override
    public SharedPreferences.Editor edit() {
        return new Editor();
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        sharedPreferences.registerOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        sharedPreferences.unregisterOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
    }

    /**
     * Wrapper for Android's {@link android.content.SharedPreferences.Editor}.
     * <p>
     * Used for modifying values in a {@link SecureSharedPreferences} object. All
     * changes you make in an editor are batched, and not copied back to the
     * original {@link SecureSharedPreferences} until you call {@link #commit()} or
     * {@link #apply()}.
     */
    public final class Editor implements SharedPreferences.Editor {
        private final SharedPreferences.Editor internalEditor;

        @SuppressLint("CommitPrefEdits")
        private Editor() {
            internalEditor = sharedPreferences.edit();
        }

        @Override
        public SharedPreferences.Editor putString(String key, String value) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, Bytes.from(value).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor putStringSet(String key, Set<String> values) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);

            final Set<String> encryptedValues = new HashSet<>(values.size());
            for (String value : values) {
                encryptedValues.add(encryptToBase64(keyHash, Bytes.from(value).array()));
            }
            internalEditor.putStringSet(keyHash, encryptedValues);
            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(String key, int value) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, Bytes.from(value).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String key, long value) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, Bytes.from(value).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String key, float value) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, ByteBuffer.allocate(4).putFloat(value).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, Bytes.from(value ? (byte) 1 : (byte) 0).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor remove(String key) {
            internalEditor.remove(encryptionProtocol.deriveContentKey(key));
            return this;
        }

        @Override
        public SharedPreferences.Editor clear() {
            internalEditor.clear();
            return this;
        }

        @Override
        public boolean commit() {
            return internalEditor.commit();
        }

        @Override
        public void apply() {
            internalEditor.apply();
        }
    }

    @NonNull
    private String encryptToBase64(String keyHash, byte[] content) {
        try {
            return Bytes.wrap(encryptionProtocol.encrypt(keyHash, password, content)).encodeBase64();
        } catch (EncryptionProtocolException e) {
            throw new IllegalStateException(e);
        }
    }

    @Nullable
    private byte[] decrypt(String keyHash, @NonNull String base64Encrypted) {
        try {
            return encryptionProtocol.decrypt(keyHash, password, Bytes.parseBase64(base64Encrypted).array());
        } catch (EncryptionProtocolException e) {
            if (recoveryPolicy.shouldRemoveBrokenContent()) {
                sharedPreferences.edit().remove(keyHash).apply();
            }
            if (recoveryPolicy.shouldThrowRuntimeException()) {
                throw new SecureSharedPreferenceCryptoException("could not decrypt " + keyHash, e);
            }
        }
        return null;
    }
}
