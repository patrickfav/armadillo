package at.favre.lib.armadillo;

import java.text.Normalizer;
import java.util.Objects;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

/**
 * A hash backed by HKDF using Hmac Sha512
 *
 * @author Patrick Favre-Bulle
 */

public final class HkdfMessageDigest implements StringMessageDigest {
    private final byte[] salt;
    private final int outLength;

    /**
     * Creates a new instance
     *
     * @param salt          used in all derivations
     * @param outByteLength the byte length created by the derive function
     */
    public HkdfMessageDigest(byte[] salt, int outByteLength) {
        this.salt = Objects.requireNonNull(salt);
        this.outLength = outByteLength;
    }

    @Override
    public String derive(String providedMessage, String usageName) {
        Objects.requireNonNull(providedMessage);
        Objects.requireNonNull(usageName);

        return Bytes.wrap(HKDF.fromHmacSha512().extractAndExpand(salt, Bytes.from(providedMessage, Normalizer.Form.NFKD).array(),
                Bytes.from(usageName, Normalizer.Form.NFKD).array(), outLength)).encodeHex();
    }
}
