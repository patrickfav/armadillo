package at.favre.lib.securepref;

/**
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

public interface KeyStretchingFunction {

    byte[] stretch(char[] password, int outLengthByte);
}
