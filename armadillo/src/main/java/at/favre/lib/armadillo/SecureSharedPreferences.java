package at.favre.lib.armadillo;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.StrictMode;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
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
@SuppressWarnings( {"unused", "WeakerAccess", "UnusedReturnValue"})
public final class SecureSharedPreferences implements ArmadilloSharedPreferences {

    private static final String PREFERENCES_SALT_KEY = "at.favre.lib.securepref.KEY_RANDOM";
    private static final String PASSWORD_VALIDATION_KEY = "at.favre.lib.securepref.PASSWORD_VALIDATION_KEY";
    private static final int PREFERENCES_SALT_LENGTH_BYTES = 32;

    private final SharedPreferences sharedPreferences;
    private final EncryptionProtocol.Factory factory;
    private final RecoveryPolicy recoveryPolicy;

    @Nullable
    private ByteArrayRuntimeObfuscator password;
    private boolean supportVerifyPassword;

    private String prefSaltContentKey;
    private byte[] preferencesSalt;
    private EncryptionProtocol encryptionProtocol;

    public SecureSharedPreferences(Context context, String preferenceName, EncryptionProtocol.Factory encryptionProtocol, @Nullable char[] password, boolean supportVerifyPassword) {
        this(context, preferenceName, encryptionProtocol, new SimpleRecoveryPolicy.Default(false, true), password, supportVerifyPassword);
    }

    public SecureSharedPreferences(Context context, String preferenceName, EncryptionProtocol.Factory encryptionProtocol, RecoveryPolicy recoveryPolicy, @Nullable char[] password, boolean supportVerifyPassword) {
        this(context.getSharedPreferences(encryptionProtocol.getStringMessageDigest().derive(preferenceName, "prefName"), Context.MODE_PRIVATE),
            encryptionProtocol, recoveryPolicy, password, supportVerifyPassword);
    }

    public SecureSharedPreferences(SharedPreferences sharedPreferences, EncryptionProtocol.Factory encryptionProtocolFactory,
                                   RecoveryPolicy recoveryPolicy, @Nullable char[] password, boolean supportVerifyPassword) {
        Timber.d("create new secure shared preferences");
        this.sharedPreferences = sharedPreferences;
        this.factory = encryptionProtocolFactory;
        this.recoveryPolicy = recoveryPolicy;
        this.password = factory.obfuscatePassword(password);
        this.supportVerifyPassword = supportVerifyPassword;
        init();
    }

    /**
     * Initialises the secure shared preferences.
     * It generates or retrieves the preferences salt, initialises the encryption protocol
     * and stores a password verification value if needed.
     */
    private void init() {
        this.preferencesSalt = getPreferencesSalt(
            factory.getStringMessageDigest(),
            factory.createDataObfuscator(),
            factory.getSecureRandom());
        this.encryptionProtocol = factory.create(preferencesSalt);
        if (supportVerifyPassword && !hasValidationValue()) {
            storePasswordValidationValue(preferencesSalt);
        }
    }

    private byte[] getPreferencesSalt(StringMessageDigest stringMessageDigest, DataObfuscator dataObfuscator, SecureRandom secureRandom) {
        prefSaltContentKey = stringMessageDigest.derive(PREFERENCES_SALT_KEY, "prefName");
        String prefSaltBase64 = sharedPreferences.getString(prefSaltContentKey, null);
        byte[] prefSalt;
        if (prefSaltBase64 == null) {
            Timber.v("create new preferences random salt");
            byte[] generatedPrefSalt = Bytes.random(PREFERENCES_SALT_LENGTH_BYTES, secureRandom).array();
            try {
                prefSalt = Bytes.wrap(generatedPrefSalt).copy().array();
                dataObfuscator.obfuscate(generatedPrefSalt);
                sharedPreferences.edit().putString(prefSaltContentKey, Bytes.wrap(generatedPrefSalt).encodeBase64()).apply();
            } finally {
                Bytes.wrapNullSafe(generatedPrefSalt).mutable().secureWipe();
            }
        } else {
            byte[] obfuscatedPrefSalt = Bytes.parseBase64(prefSaltBase64).array();
            dataObfuscator.deobfuscate(obfuscatedPrefSalt);
            prefSalt = obfuscatedPrefSalt;
        }
        return prefSalt;
    }

    /**
     * Checks whether a validation value is already stored.
     */
    private boolean hasValidationValue() {
        return contains(PASSWORD_VALIDATION_KEY);
    }

    /**
     * Encrypts and stores a known value (preferencesSalt) to be able to verify the password in the future.
     */
    private void storePasswordValidationValue(byte[] passwordValidationValue) {
        edit().putString(PASSWORD_VALIDATION_KEY, Bytes.wrap(passwordValidationValue).encodeBase64()).apply();
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
            if (!key.equals(prefSaltContentKey)) {
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

    private final List<SharedPreferenceChangeListenerWrapper> securePreferenceListeners = new LinkedList<>();

    @Override
    public void registerOnSecurePreferenceChangeListener(@NonNull OnSecurePreferenceChangeListener listener) {
        synchronized (securePreferenceListeners) {
            SharedPreferenceChangeListenerWrapper listenerWrapper = new SharedPreferenceChangeListenerWrapper(listener, encryptionProtocol, this);
            registerOnSharedPreferenceChangeListener(listenerWrapper);
            securePreferenceListeners.add(listenerWrapper);
        }
    }

    @Override
    public void unregisterOnSecurePreferenceChangeListener(@NonNull OnSecurePreferenceChangeListener listener) {
        synchronized (securePreferenceListeners) {
            ListIterator<SharedPreferenceChangeListenerWrapper> iterator = securePreferenceListeners.listIterator();
            while (iterator.hasNext()) {
                SharedPreferenceChangeListenerWrapper listenerWrapper = iterator.next();
                OnSecurePreferenceChangeListener wrapped = listenerWrapper.getWrapped();
                if (wrapped == null || wrapped == listener) {
                    unregisterOnSharedPreferenceChangeListener(listenerWrapper);
                    iterator.remove();
                }
            }
        }
    }

    @Override
    public void changePassword(@Nullable char[] newPassword) {
        changePassword(newPassword, null);
    }

    @Override
    public boolean isValidPassword() {
        StrictMode.noteSlowCall("checking password should only be done in a background thread");
        if (!supportVerifyPassword) {
            throw new UnsupportedOperationException("support verify password is not enabled");
        }
        try {
            String storedValue = getString(PASSWORD_VALIDATION_KEY, null);
            return storedValue != null && Bytes.parseBase64(storedValue).equalsConstantTime(preferencesSalt);
        } catch (SecureSharedPreferenceCryptoException e) {
            return false;
        }
    }

    @SuppressLint("ApplySharedPref")
    @Override
    public void changePassword(@Nullable char[] newPassword, @Nullable KeyStretchingFunction newKsFunction) {
        StrictMode.noteSlowCall("changing password should only be done in a background thread");

        newPassword = newPassword == null || newPassword.length == 0 ? null : newPassword;

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

        if (password != null) {
            password.wipe();
        }
        password = encryptionProtocol.obfuscatePassword(newPassword);
    }

    /**
     * Re-encrypts String stored with given key hash using the new provided password.
     *
     * @param newPassword   new password with whom re-encrypt the String.
     * @param editor        {@link Editor}.
     * @param keyHash       key hash of the String to re-encrypt.
     * @param newKsFunction new key stretching function (or null to use the same one).
     * @return returns true if the String was successfully re-encrypted.
     */
    private boolean reencryptStringType(@Nullable char[] newPassword, Editor editor, String keyHash, @Nullable KeyStretchingFunction newKsFunction) {
        try {
            final ByteArrayRuntimeObfuscator pw = encryptionProtocol.obfuscatePassword(newPassword);
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

            editor.putEncryptedBase64(keyHash, encryptToBase64(keyHash, pw, bytes));
            return true;
        } catch (ClassCastException e) {
            return false;
        }
    }

    /**
     * Re-encrypts StringSet stored with given key hash using the new provided password.
     *
     * @param newPassword   new password with whom re-encrypt the StringSet.
     * @param editor        {@link Editor}.
     * @param keyHash       key hash of the StringSet to re-encrypt.
     * @param newKsFunction new key stretching function (or null to use the same one).
     * @return returns true if the StringSet was successfully re-encrypted.
     */
    private boolean reencryptStringSetType(char[] newPassword, Editor editor, String keyHash, @Nullable KeyStretchingFunction newKsFunction) {
        final ByteArrayRuntimeObfuscator pw = encryptionProtocol.obfuscatePassword(newPassword);
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
            encryptedValues.add(encryptToBase64(keyHash, pw, Bytes.from(value).array()));
        }
        editor.putEncryptedStringSet(keyHash, encryptedValues);
        return true;
    }

    @Override
    public void close() {
        if (password != null) {
            password.wipe();
        }
        password = null;
        if (preferencesSalt != null) {
            Arrays.fill(preferencesSalt, (byte) 0);
        }
        encryptionProtocol.wipeDerivedPasswordCache();
        preferencesSalt = null;
        prefSaltContentKey = null;
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
            internalEditor.putString(keyHash, encryptToBase64(keyHash, password, Bytes.from(value).array()));
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
                init();
            }
        }
    }

    @NonNull
    private String encryptToBase64(String keyHash, @Nullable ByteArrayRuntimeObfuscator password, byte[] content) {
        try {
            return Bytes.wrap(encryptionProtocol.encrypt(keyHash, encryptionProtocol.deobfuscatePassword(password), content)).encodeBase64();
        } catch (EncryptionProtocolException e) {
            throw new IllegalStateException(e);
        }
    }

    @Nullable
    private byte[] decrypt(String keyHash, @Nullable ByteArrayRuntimeObfuscator password, @NonNull String base64Encrypted) {
        try {
            return encryptionProtocol.decrypt(keyHash, encryptionProtocol.deobfuscatePassword(password), Bytes.parseBase64(base64Encrypted).array());
        } catch (EncryptionProtocolException e) {
            recoveryPolicy.handleBrokenContent(e, keyHash, base64Encrypted, password != null, this);
        }
        return null;
    }

}
