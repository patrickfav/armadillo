package at.favre.lib.armadillo;

import android.content.SharedPreferences;

/**
 * Extending the {@link SharedPreferences} interface this exports additional APIs specific
 * to armadillo.
 */
public interface ArmadilloSharedPreferences extends SharedPreferences {

    /**
     * Changes the user provided password to the new given password. This will immediately reencrypt
     * all the key/value entries with the new password and the data won't be accessible with the old
     * one anymore. This process is atomic, if an exception happens during it, nothing will change.
     * <p>
     * Warning: Depending on the use key stretching function and count of saved data this is a very
     * expensive call.
     *
     * @param newPassword which will be additionally used to create the key for the encryption
     */
    void changePassword(char[] newPassword);

    /**
     * Clears most of the internal state and makes the instance unusable
     */
    void close();
}
