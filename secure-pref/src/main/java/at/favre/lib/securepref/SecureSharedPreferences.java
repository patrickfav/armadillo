package at.favre.lib.securepref;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

/**
 * @author RISE GmbH (patrick.favre@rise-world.com)
 * @since 18.12.2017
 */

public class SecureSharedPreferences implements SharedPreferences {

    private final static String KEY_RANDOM = "at.favre.lib.securepref.KEY_RANDOM";

    private final SharedPreferences sharedPreferences;
    private final EncryptionProtocol encryptionProtocol;
    private final SecureRandom secureRandom;
    private final char[] password;

    public SecureSharedPreferences(Context context, String preferenceName, EncryptionProtocol encryptionProtocol) {
        this(context, preferenceName, encryptionProtocol, null, new SecureRandom());
    }

    public SecureSharedPreferences(Context context, String preferenceName, EncryptionProtocol encryptionProtocol, SecureRandom secureRandom) {
        this(context, preferenceName, encryptionProtocol, null, secureRandom);
    }

    public SecureSharedPreferences(Context context, String preferenceName, EncryptionProtocol encryptionProtocol, char[] password, SecureRandom secureRandom) {
        this(context.getSharedPreferences(deriveKey(preferenceName), Context.MODE_PRIVATE), encryptionProtocol, password, secureRandom);
    }

    public SecureSharedPreferences(SharedPreferences sharedPreferences, EncryptionProtocol encryptionProtocol, char[] password, SecureRandom secureRandom) {
        this.sharedPreferences = sharedPreferences;
        this.encryptionProtocol = encryptionProtocol;
        this.secureRandom = secureRandom;
        this.password = password;
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
        final String keyHash = deriveKey(key);
        final String encryptedValue = sharedPreferences.getString(keyHash, null);
        if (encryptedValue == null) {
            return defaultValue;
        }

        return Bytes.from(decrypt(keyHash, encryptedValue)).encodeUtf8();
    }

    @Override
    public Set<String> getStringSet(String key, Set<String> defaultValues) {
        final String keyHash = deriveKey(key);
        final Set<String> encryptedSet = sharedPreferences.getStringSet(keyHash, null);
        if (encryptedSet == null) {
            return defaultValues;
        }

        final Set<String> decryptedSet = new HashSet<>(encryptedSet.size());

        for (String encryptedValue : encryptedSet) {
            decryptedSet.add(Bytes.from(decrypt(keyHash, encryptedValue)).encodeUtf8());
        }
        return decryptedSet;
    }

    @Override
    public int getInt(String key, int defaultValue) {
        final String keyHash = deriveKey(key);
        final String encryptedValue = sharedPreferences.getString(keyHash, null);
        if (encryptedValue == null) {
            return defaultValue;
        }
        return Bytes.from(decrypt(keyHash, encryptedValue)).toInt();
    }

    @Override
    public long getLong(String key, long defaultValue) {
        final String keyHash = deriveKey(key);
        final String encryptedValue = sharedPreferences.getString(keyHash, null);
        if (encryptedValue == null) {
            return defaultValue;
        }

        return Bytes.from(decrypt(keyHash, encryptedValue)).toLong();
    }

    @Override
    public float getFloat(String key, float defaultValue) {
        final String keyHash = deriveKey(key);
        final String encryptedValue = sharedPreferences.getString(keyHash, null);
        if (encryptedValue == null) {
            return defaultValue;
        }

        return Bytes.from(decrypt(keyHash, encryptedValue)).toFloat();
    }

    @Override
    public boolean getBoolean(String key, boolean defaultValue) {
        final String keyHash = deriveKey(key);
        final String encryptedValue = sharedPreferences.getString(keyHash, null);
        if (encryptedValue == null) {
            return defaultValue;
        }

        return decrypt(keyHash, encryptedValue)[0] != 0;
    }

    @Override
    public boolean contains(String key) {
        return sharedPreferences.contains(deriveKey(key));
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
        private SharedPreferences.Editor internalEditor;

        @SuppressLint("CommitPrefEdits")
        private Editor() {
            internalEditor = sharedPreferences.edit();
        }

        @Override
        public SharedPreferences.Editor putString(String key, String value) {
            final String keyHash = deriveKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, Bytes.from(value).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor putStringSet(String key, Set<String> values) {
            final String keyHash = deriveKey(key);

            final Set<String> encryptedValues = new HashSet<>(values.size());
            for (String value : values) {
                encryptedValues.add(encryptToBase64(keyHash, Bytes.from(value).array()));
            }
            internalEditor.putStringSet(keyHash, encryptedValues);
            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(String key, int value) {
            final String keyHash = deriveKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, Bytes.from(value).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String key, long value) {
            final String keyHash = deriveKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, Bytes.from(value).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String key, float value) {
            final String keyHash = deriveKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, ByteBuffer.allocate(4).putFloat(value).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            final String keyHash = deriveKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, Bytes.from(value ? (byte) 1 : (byte) 0).array()))
            ;
            return this;
        }

        @Override
        public SharedPreferences.Editor remove(String key) {
            internalEditor.remove(deriveKey(key));
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
            return Bytes.wrap(encryptionProtocol.encrypt(keyHash + getPreferenceRandom(), password, content)).encodeBase64();
        } catch (EncryptionProtocolException e) {
            throw new IllegalStateException(e);
        }
    }

    @NonNull
    private byte[] decrypt(String keyHash, @NonNull String base64Encrypted) {
        try {
            return encryptionProtocol.decrypt(keyHash + getPreferenceRandom(), password, Bytes.parseBase64(base64Encrypted).array());
        } catch (EncryptionProtocolException e) {
            throw new IllegalStateException(e);
        }
    }

    private String getPreferenceRandom() {
        final String keyHash = deriveKey(KEY_RANDOM);
        String base64Random = sharedPreferences.getString(keyHash, null);
        if (base64Random == null) {
            base64Random = Bytes.random(32, secureRandom).encodeBase64();
            sharedPreferences.edit().putString(keyHash, base64Random).apply();
        }
        return base64Random;
    }

    private static String deriveKey(String contentKey) {
        return Bytes.wrap(HKDF.fromHmacSha256().extract(BuildConfig.PREF_SALT, Bytes.from(contentKey, Normalizer.Form.NFKD).array())).encodeHex();
    }
}
