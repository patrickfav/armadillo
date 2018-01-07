package at.favre.lib.armadillo;

/**
 * Exception thrown during {@link EncryptionProtocol} encrypt or decrpyt
 *
 * @author Patrick Favre-Bulle
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
