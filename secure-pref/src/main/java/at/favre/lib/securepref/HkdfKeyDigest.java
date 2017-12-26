package at.favre.lib.securepref;

import java.text.Normalizer;
import java.util.Objects;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

/**
 * @author RISE GmbH (patrick.favre@rise-world.com)
 * @since 26.12.2017
 */

public class HkdfKeyDigest implements ContentKeyDigest {
    private final byte[] salt;
    private final int outLength;

    public HkdfKeyDigest(byte[] salt, int outLength) {
        this.salt = salt;
        this.outLength = outLength;
    }

    @Override
    public String derive(String keyName, String usageName) {
        Objects.requireNonNull(keyName);
        Objects.requireNonNull(usageName);

        return Bytes.wrap(HKDF.fromHmacSha512().extractAndExpand(salt, Bytes.from(keyName, Normalizer.Form.NFKD).array(),
                Bytes.from(usageName, Normalizer.Form.NFKD).array(), outLength)).encodeHex();
    }
}
