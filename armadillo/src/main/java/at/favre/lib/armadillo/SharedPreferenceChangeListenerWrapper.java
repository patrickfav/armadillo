package at.favre.lib.armadillo;

import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.lang.ref.WeakReference;

/**
 * Implementation that will wrap a {@link OnSecurePreferenceChangeListener} to adapt to the standard {@link SharedPreferences.OnSharedPreferenceChangeListener}
 * @since 03.07.2019
 */
final class SharedPreferenceChangeListenerWrapper implements SharedPreferences.OnSharedPreferenceChangeListener {

    private static class KeyComparissonImpl implements OnSecurePreferenceChangeListener.DerivedKeyComparison {
        private final EncryptionProtocol encryptionProtocol;

        private KeyComparissonImpl(EncryptionProtocol encryptionProtocol) {
            this.encryptionProtocol = encryptionProtocol;
        }

        @Override
        public boolean isDerivedKeyEqualTo(@NonNull String derivedKey, @NonNull String key) {
            return derivedKey.equals(encryptionProtocol.deriveContentKey(key));
        }
    }

    private final OnSecurePreferenceChangeListener.DerivedKeyComparison keyComparison;
    private final WeakReference<OnSecurePreferenceChangeListener> wrappedRef;

    SharedPreferenceChangeListenerWrapper(@NonNull OnSecurePreferenceChangeListener wrapped, @NonNull EncryptionProtocol encryptionProtocol) {
        keyComparison = new KeyComparissonImpl(encryptionProtocol);
        wrappedRef = new WeakReference<>(wrapped);
    }

    @Nullable
    OnSecurePreferenceChangeListener getWrapped() {
        return wrappedRef.get();
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {

        OnSecurePreferenceChangeListener wrapped = wrappedRef.get();

        if (wrapped == null && sharedPreferences != null) {
            // we unregister ourselves from client preferences
            sharedPreferences.unregisterOnSharedPreferenceChangeListener(this);
            return;
        }

        if (sharedPreferences != null && key != null) {
            wrapped.onSecurePreferenceChanged(keyComparison, sharedPreferences, key);
        }
    }
}
