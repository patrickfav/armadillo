package at.favre.lib.armadillo;

/**
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */
public class EncryptionProtocolException extends Exception {

    public EncryptionProtocolException(String message) {
        super(message);
    }

    public EncryptionProtocolException(String message, Throwable cause) {
        super(message, cause);
    }

    public EncryptionProtocolException(Throwable cause) {
        super(cause);
    }
}
