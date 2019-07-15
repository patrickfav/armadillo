package at.favre.lib.armadillo;

import android.content.SharedPreferences;
import android.support.annotation.NonNull;

/**
 * Allow to register preference change listeners that receive a {@link DerivedKeyComparison} instance in order to make it possible compare the changed key against
 * actual key constants.
 *
 * <pre>
 *     public class SampleActivity extends AppCompatActivity {
 *         private final String KEY_TOKEN = "token";
 *         private final OnSecurePreferenceChangeListener onSecurePreferenceChangeListener = (sharedPreferences, comparison) -> {
 *             if (comparison.isDerivedKeyEqualTo(KEY_TOKEN)) {
 *
 *                 String newToken = sharedPreferences.getString(KEY_TOKEN, null);
 *                 onTokenUpdated(newToken);
 *             }
 *         };
 *
 *         private void onTokenUpdated(String newToken) {
 *             // Do whatever is required when underlying token has been updated
 *         }
 *
 *         &#64;Overrides
 *         protected void onCreate(Bundle savedInstanceState) {
 *             super.onCreate(savedInstanceState);
 *             // ... initialize encrypted preferences ...
 *             encryptedPreferences.registerOnSecurePreferenceChangeListener(onSecurePreferenceChangeListener);
 *         }
 *    }
 * </pre>
 *
 * @since 0.9.0
 */
public interface OnSecurePreferenceChangeListener {

    /**
     * Variation of the regular {@link android.content.SharedPreferences.OnSharedPreferenceChangeListener#onSharedPreferenceChanged(SharedPreferences, String)} that
     * provides a {@link DerivedKeyComparison} to allow client side react only to a specific changed key
     * @param sharedPreferences the shared preferences instance
     * @param comparison utility to check equivalence between plain keys and derived keys
     */
    void onSecurePreferenceChanged(@NonNull SharedPreferences sharedPreferences, @NonNull DerivedKeyComparison comparison);

    /**
     * Allows client side {@link OnSecurePreferenceChangeListener} to check if the changed key is the key of interest.
     */
    interface DerivedKeyComparison {

        /**
         * Checks if the given key is equal to the derivedContentKey that changed which is undisclosed.
         * @param key is the plain key to check equality against derivedContentKey
         * @return true if given key is equal to the contained <em>derivedContentKey</em>
         */
        boolean isDerivedKeyEqualTo(@NonNull String key);
    }
}
