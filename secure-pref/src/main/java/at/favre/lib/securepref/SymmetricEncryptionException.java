package at.favre.lib.securepref;

/**
 * @author RISE GmbH (patrick.favre@rise-world.com)
 * @since 18.12.2017
 */

public class SymmetricEncryptionException extends Exception {

    public SymmetricEncryptionException(String message) {
        super(message);
    }

    public SymmetricEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
