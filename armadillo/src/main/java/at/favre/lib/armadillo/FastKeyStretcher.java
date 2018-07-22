package at.favre.lib.armadillo;

import java.text.Normalizer;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

/**
 * This is a implementation for a key derivation function with disabled key stretching function.
 * Using this will circumvent the brute force prevention of password hashing functions like bcrypt.
 *
 * @author patrick.favrebulle@gmail.com
 */

public final class FastKeyStretcher implements KeyStretchingFunction {
    @Override
    public byte[] stretch(byte[] salt, char[] password, int outLengthByte) {
        return HKDF.fromHmacSha256().extractAndExpand(salt, Bytes.from(String.valueOf(password), Normalizer.Form.NFKD).array(),
                "FastKeyStretcher".getBytes(), outLengthByte);
    }
}
