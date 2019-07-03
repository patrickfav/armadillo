package at.favre.lib.armadillo;

import android.content.SharedPreferences;
import android.support.annotation.NonNull;

/**
 * Allow to register preference change listeners that receive
 * @since 03.07.2019
 */
public interface OnSecurePreferenceChangeListener {

    /**
     * Variation of the regular {@link android.content.SharedPreferences.OnSharedPreferenceChangeListener#onSharedPreferenceChanged(SharedPreferences, String)} that
     * provides a {@link DerivedKeyComparison} to allow client side react only to a specific changed key
     * @param comparison utility to check equivalence between plain keys and derived keys
     * @param sharedPreferences the shared preferences instance
     * @param derivedKeyChanged the value of the changed key in it's derived form (as it's actually stored)
     */
    void onSecurePreferenceChanged(@NonNull DerivedKeyComparison comparison, @NonNull SharedPreferences sharedPreferences, @NonNull String derivedKeyChanged);

    /**
     * Allows client side {@link OnSecurePreferenceChangeListener} to check if the changed key is the key of interest.
     */
    interface DerivedKeyComparison {

        /**
         * Checks if the given derivedKey and key are equivalent.
         * @param derivedKey is derived key returned on method
         * @param key is the plain key to check equality against derivedKey
         * @return
         */
        boolean isDerivedKeyEqualTo(@NonNull String derivedKey, @NonNull String key);
    }
}
