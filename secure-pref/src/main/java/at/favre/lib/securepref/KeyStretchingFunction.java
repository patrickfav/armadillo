package at.favre.lib.securepref;

/**
 * @author RISE GmbH (patrick.favre@rise-world.com)
 * @since 18.12.2017
 */

public interface KeyStretchingFunction {

    byte[] stretch(char[] password, int outLengthByte);
}
