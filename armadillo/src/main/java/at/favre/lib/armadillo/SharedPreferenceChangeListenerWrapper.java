package at.favre.lib.armadillo;

import android.content.SharedPreferences;
import android.support.annotation.NonNull;

/**
 * Implementation that will wrap a {@link OnSecurePreferenceChangeListener} to adapt to the standard {@link SharedPreferences.OnSharedPreferenceChangeListener}
 * @since 0.9.0
 */
final class SharedPreferenceChangeListenerWrapper implements SharedPreferences.OnSharedPreferenceChangeListener {

    private static final class KeyComparisonImpl implements OnSecurePreferenceChangeListener.DerivedKeyComparison {
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

    private final OnSecurePreferenceChangeListener wrappedListener;
    @NonNull private final EncryptionProtocol encryptionProtocol;
    @NonNull private final SharedPreferences securedPrefs;

    SharedPreferenceChangeListenerWrapper(@NonNull OnSecurePreferenceChangeListener wrapped, @NonNull EncryptionProtocol encryptionProtocol, @NonNull SharedPreferences securedPrefs) {
        wrappedListener = wrapped;
        this.encryptionProtocol = encryptionProtocol;
        this.securedPrefs = securedPrefs;
    }

    OnSecurePreferenceChangeListener getWrapped() {
        return wrappedListener;
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {

        if (key != null) {
            wrappedListener.onSecurePreferenceChanged(securedPrefs, new KeyComparisonImpl(encryptionProtocol, key));
        }
    }
}
