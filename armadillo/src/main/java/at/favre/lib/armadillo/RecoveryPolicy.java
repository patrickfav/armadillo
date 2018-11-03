package at.favre.lib.armadillo;

import android.support.annotation.NonNull;

/**
 * Defines how the storage should behave on errors while decrypting.
 * <p>
 * For a simpler version check out {@link SimpleRecoveryPolicy}, this is for more advanced
 * use cases.
 *
 * @author Patrick Favre-Bulle
 */

public interface RecoveryPolicy {

    /**
     * When a value cannot be decrypted, this method will be called
     *
     * @param e                 thrown exception
     * @param keyHash           hash of the key that was called
     * @param base64Encrypted   encrypted data in base64 encoding
     * @param userPasswordUsed  if a user password was used to decrypt the storage
     * @param sharedPreferences currently used shared preference (be aware if you modify)
     * @throws SecureSharedPreferenceCryptoException if you want to throw an exception, use or wrap in this typ
     */
    void handleBrokenContent(EncryptionProtocolException e, String keyHash, @NonNull String base64Encrypted,
                             boolean userPasswordUsed, ArmadilloSharedPreferences sharedPreferences)
        throws SecureSharedPreferenceCryptoException;
}
