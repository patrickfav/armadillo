package at.favre.lib.armadillo;

/**
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

public class AuthenticatedEncryptionException extends Exception {

    public AuthenticatedEncryptionException(String message) {
        super(message);
    }

    public AuthenticatedEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
