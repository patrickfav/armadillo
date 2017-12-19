package at.favre.lib.securepref;

import android.support.annotation.NonNull;

/**
 * @author RISE GmbH (patrick.favre@rise-world.com)
 * @since 18.12.2017
 */

public interface EncryptionProtocol {

    byte[] encrypt(@NonNull String contentKey, byte[] rawContent) throws EncryptionProtocolException;

    byte[] encrypt(@NonNull String contentKey, char[] password, byte[] rawContent) throws EncryptionProtocolException;

    byte[] decrypt(@NonNull String contentKey, byte[] encryptedContent) throws EncryptionProtocolException;

    byte[] decrypt(@NonNull String contentKey, char[] password, byte[] encryptedContent) throws EncryptionProtocolException;

}
