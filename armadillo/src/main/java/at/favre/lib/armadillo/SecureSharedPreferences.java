package at.favre.lib.armadillo;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.StrictMode;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import at.favre.lib.bytes.Bytes;
import timber.log.Timber;

/**
 * A simple wrapper implementation using the {@link DefaultEncryptionProtocol} before persisting
 * the data. It deviates from the expected behaviour in the following way:
 * <p>
 * <ul>
 * <li>The storage adds a meta entry containing a storage scoped salt value</li>
 * <li>getAll() will return the hashed keys and an empty string as content</li>
 * <li>getAll() will NOT include the storage salt (i.e size of the returned map only reflects the user added values)</li>
 * </ul>
 *
 * @author Patrick Favre-Bulle
 */
public final class SecureSharedPreferences implements ArmadilloSharedPreferences {

    private static final String PREFERENCES_SALT_KEY = "at.favre.lib.securepref.KEY_RANDOM";
    private static final int PREFERENCES_SALT_LENGTH_BYTES = 32;

    private final SharedPreferences sharedPreferences;
    private final EncryptionProtocol.Factory factory;
    private final RecoveryPolicy recoveryPolicy;
    private char[] password;
    private String preferenceRandomContentKey;
    private EncryptionProtocol encryptionProtocol;

    public SecureSharedPreferences(Context context, String preferenceName, EncryptionProtocol.Factory encryptionProtocol, char[] password) {
        this(context, preferenceName, encryptionProtocol, new RecoveryPolicy.Default(false, true), password);
    }

    public SecureSharedPreferences(Context context, String preferenceName, EncryptionProtocol.Factory encryptionProtocol, RecoveryPolicy recoveryPolicy, char[] password) {
        this(context.getSharedPreferences(encryptionProtocol.getStringMessageDigest().derive(preferenceName, "prefName"), Context.MODE_PRIVATE),
                encryptionProtocol, recoveryPolicy, password);
    }

    public SecureSharedPreferences(SharedPreferences sharedPreferences, EncryptionProtocol.Factory encryptionProtocolFactory,
                                   RecoveryPolicy recoveryPolicy, char[] password) {
        Timber.d("create new secure shared preferences");
        this.sharedPreferences = sharedPreferences;
        this.recoveryPolicy = recoveryPolicy;
        this.password = password;
        this.factory = encryptionProtocolFactory;
        createProtocol();
    }

    private void createProtocol() {
        encryptionProtocol = factory.create(
                getPreferencesSalt(
                        factory.getStringMessageDigest(),
                        factory.createDataObfuscator(),
                        factory.getSecureRandom()));
    }

    private byte[] getPreferencesSalt(StringMessageDigest stringMessageDigest, DataObfuscator dataObfuscator, SecureRandom secureRandom) {
        preferenceRandomContentKey = stringMessageDigest.derive(PREFERENCES_SALT_KEY, "prefName");
        String base64Random = sharedPreferences.getString(preferenceRandomContentKey, null);
        byte[] outBytes;
        if (base64Random == null) {
            Timber.v("create new preferences random salt");
            byte[] rndBytes = Bytes.random(PREFERENCES_SALT_LENGTH_BYTES, secureRandom).array();
            try {
                outBytes = Bytes.from(rndBytes).array();
                dataObfuscator.obfuscate(rndBytes);
                sharedPreferences.edit().putString(preferenceRandomContentKey, Bytes.wrap(rndBytes).encodeBase64()).apply();
            } finally {
                Bytes.wrapNullSafe(rndBytes).mutable().secureWipe();
            }
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
            if (!key.equals(preferenceRandomContentKey)) {
                keyOnlyMap.put(key, "");
            }
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

        byte[] bytes = decrypt(keyHash, password, encryptedValue);
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
            byte[] bytes = decrypt(keyHash, password, encryptedValue);
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

        byte[] bytes = decrypt(keyHash, password, encryptedValue);
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

        byte[] bytes = decrypt(keyHash, password, encryptedValue);
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

        byte[] bytes = decrypt(keyHash, password, encryptedValue);
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

        byte[] bytes = decrypt(keyHash, password, encryptedValue);
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

    @Override
    public void changePassword(char[] newPassword) {
        changePassword(newPassword, null);
    }

    @SuppressLint("ApplySharedPref")
    @Override
    public void changePassword(char[] newPassword, @Nullable KeyStretchingFunction newKsFunction) {
        StrictMode.noteSlowCall("changing password should only be done in a background thread");
        SharedPreferences.Editor editor = this.edit();
        KeyStretchingFunction currentFunction = encryptionProtocol.getKeyStretchingFunction();

        for (String keyHash : getAll().keySet()) {
            encryptionProtocol.setKeyStretchingFunction(currentFunction);
            if (!reencryptStringType(newPassword, (Editor) editor, keyHash, newKsFunction)) {
                reencryptStringSetType(newPassword, (Editor) editor, keyHash, newKsFunction);
            }
        }
        editor.commit();

        if (newKsFunction != null) {
            encryptionProtocol.setKeyStretchingFunction(newKsFunction);
        }

        Arrays.fill(password, (char) 0);
        password = newPassword;
    }

    private boolean reencryptStringType(char[] newPassword, Editor editor, String keyHash, @Nullable KeyStretchingFunction newKsFunction) {
        try {
            final String encryptedValue = sharedPreferences.getString(keyHash, null);

            if (encryptedValue == null) {
                return false;
            }

            byte[] bytes = decrypt(keyHash, password, encryptedValue);
            if (bytes == null) {
                return true;
            }

            if (newKsFunction != null) {
                encryptionProtocol.setKeyStretchingFunction(newKsFunction);
            }

            editor.putEncryptedBase64(keyHash, encryptToBase64(keyHash, newPassword, bytes));
            return true;
        } catch (ClassCastException e) {
            return false;
        }
    }

    private boolean reencryptStringSetType(char[] newPassword, Editor editor, String keyHash, @Nullable KeyStretchingFunction newKsFunction) {
        final Set<String> encryptedSet = sharedPreferences.getStringSet(keyHash, null);
        if (encryptedSet == null) {
            return false;
        }

        final Set<String> decryptedSet = new HashSet<>(encryptedSet.size());
        for (String encryptedValue : encryptedSet) {
            byte[] bytes = decrypt(keyHash, password, encryptedValue);
            if (bytes == null) {
                continue;
            }
            decryptedSet.add(Bytes.from(bytes).encodeUtf8());
        }

        if (newKsFunction != null) {
            encryptionProtocol.setKeyStretchingFunction(newKsFunction);
        }

        final Set<String> encryptedValues = new HashSet<>(decryptedSet.size());
        for (String value : decryptedSet) {
            encryptedValues.add(encryptToBase64(keyHash, newPassword, Bytes.from(value).array()));
        }
        editor.putEncryptedStringSet(keyHash, encryptedValues);
        return true;
    }

    @Override
    public void close() {
        Arrays.fill(password, (char) 0);
        preferenceRandomContentKey = null;
        encryptionProtocol = null;
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
        private boolean clear = false;

        @SuppressLint("CommitPrefEdits")
        private Editor() {
            internalEditor = sharedPreferences.edit();
        }

        @Override
        public SharedPreferences.Editor putString(String key, @Nullable String value) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);

            if (value == null) {
                internalEditor.remove(encryptionProtocol.deriveContentKey(key));
            } else {
                internalEditor.putString(keyHash, encryptToBase64(keyHash, password, Bytes.from(value).array()));
            }
            return this;
        }

        SharedPreferences.Editor putEncryptedBase64(String key, @Nullable String value) {
            internalEditor.putString(key, value);
            return this;
        }

        @Override
        public SharedPreferences.Editor putStringSet(String key, @Nullable Set<String> values) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);

            if (values == null) {
                internalEditor.remove(encryptionProtocol.deriveContentKey(key));
            } else {
                final Set<String> encryptedValues = new HashSet<>(values.size());
                for (String value : values) {
                    encryptedValues.add(encryptToBase64(keyHash, password, Bytes.from(value).array()));
                }
                internalEditor.putStringSet(keyHash, encryptedValues);
            }
            return this;
        }

        SharedPreferences.Editor putEncryptedStringSet(String key, @Nullable Set<String> values) {
            internalEditor.putStringSet(key, values);
            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(String key, int value) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, password, Bytes.from(value).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String key, long value) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, password, Bytes.from(value).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String key, float value) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, password, ByteBuffer.allocate(4).putFloat(value).array()));
            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            final String keyHash = encryptionProtocol.deriveContentKey(key);
            internalEditor.putString(keyHash, encryptToBase64(keyHash, password, Bytes.from(value ? (byte) 1 : (byte) 0).array()));
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
            clear = true;
            return this;
        }

        @Override
        public boolean commit() {
            try {
                return internalEditor.commit();
            } finally {
                handlePossibleClear();
            }
        }

        @Override
        public void apply() {
            internalEditor.apply();
            handlePossibleClear();
        }

        private void handlePossibleClear() {
            if (clear) {
                createProtocol();
            }
        }
    }

    @NonNull
    private String encryptToBase64(String keyHash, char[] password, byte[] content) {
        try {
            return Bytes.wrap(encryptionProtocol.encrypt(keyHash, password, content)).encodeBase64();
        } catch (EncryptionProtocolException e) {
            throw new IllegalStateException(e);
        }
    }

    @Nullable
    private byte[] decrypt(String keyHash, char[] password, @NonNull String base64Encrypted) {
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
