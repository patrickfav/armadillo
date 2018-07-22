package at.favre.lib.armadillo;

import android.content.SharedPreferences;
import android.support.annotation.Nullable;

/**
 * Extending the {@link SharedPreferences} interface this exports additional APIs specific
 * to armadillo.
 */
public interface ArmadilloSharedPreferences extends SharedPreferences {

    /**
     * Changes the user provided password to the new given password and sets a new stretching function.
     * This will immediately reencrypt all the key/value entries with the new password and the data
     * won't be accessible with the old one anymore. This process is atomic, if an exception happens
     * during it, nothing will change.
     * <p>
     * This method can be used to switch from a generated key to a key derived from user-provided password.
     * <p>
     * A null or zero length password will reset the password (as if no user-provided password is set).
     * <p>
     * Warning: Depending on the use key stretching function and count of saved data this is a very
     * expensive call.
     *
     * @param newPassword which will be additionally used to create the key for the encryption
     * @param function    set a new function to be used the encrypt with new password. It will be
     *                    ignored if null is passed.
     */
    void changePassword(@Nullable char[] newPassword, @Nullable KeyStretchingFunction function);

    /**
     * Changes the user provided password to the new given password. This will immediately reencrypt
     * all the key/value entries with the new password and the data won't be accessible with the old
     * one anymore. This process is atomic, if an exception happens during it, nothing will change.
     * <p>
     * This method can be used to switch from a generated key to a key derived from user-provided password.
     * <p>
     * A null or zero length password will reset the password (as if no user-provided password is set).
     * <p>
     * Warning: Depending on the use key stretching function and count of saved data this is a very
     * expensive call.
     *
     * @param newPassword which will be additionally used to create the key for the encryption
     */
    void changePassword(@Nullable char[] newPassword);

    /**
     * Clears most of the internal state and makes the instance unusable.
     * User-provided password is cleared.
     */
    void close();
}
