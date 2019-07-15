package at.favre.lib.armadillo;

import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.lang.ref.WeakReference;

/**
 * Implementation that will wrap a {@link OnSecurePreferenceChangeListener} to adapt to the standard {@link SharedPreferences.OnSharedPreferenceChangeListener}
 * @since 0.9.0
 */
final class SharedPreferenceChangeListenerWrapper implements SharedPreferences.OnSharedPreferenceChangeListener {

    private static class KeyComparisonImpl implements OnSecurePreferenceChangeListener.DerivedKeyComparison {
        private final EncryptionProtocol encryptionProtocol;
        private final String derivedContentKey;

        private KeyComparisonImpl(EncryptionProtocol encryptionProtocol, String derivedContentKey) {
            this.encryptionProtocol = encryptionProtocol;
            this.derivedContentKey = derivedContentKey;
        }

        @Override
        public boolean isDerivedKeyEqualTo(@NonNull String key) {
            return derivedContentKey.equals(encryptionProtocol.deriveContentKey(key));
        }
    }

    private final WeakReference<OnSecurePreferenceChangeListener> wrappedRef;
    @NonNull private final EncryptionProtocol                     encryptionProtocol;
    @NonNull private final SharedPreferences securedPrefs;

    SharedPreferenceChangeListenerWrapper(@NonNull OnSecurePreferenceChangeListener wrapped, @NonNull EncryptionProtocol encryptionProtocol, @NonNull SharedPreferences securedPrefs) {
        wrappedRef = new WeakReference<>(wrapped);
        this.encryptionProtocol = encryptionProtocol;
        this.securedPrefs = securedPrefs;
    }

    @Nullable
    OnSecurePreferenceChangeListener getWrapped() {
        return wrappedRef.get();
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {

        OnSecurePreferenceChangeListener wrapped = wrappedRef.get();

        if (wrapped == null) {
            // we unregister ourselves from client preferences
            sharedPreferences.unregisterOnSharedPreferenceChangeListener(this);
            return;
        }

        if (key != null) {
            wrapped.onSecurePreferenceChanged(securedPrefs, new KeyComparisonImpl(encryptionProtocol, key));
        }
    }
}
