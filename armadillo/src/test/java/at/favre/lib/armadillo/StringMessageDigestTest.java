package at.favre.lib.armadillo;

import org.junit.Before;
import org.junit.Test;

import at.favre.lib.bytes.Bytes;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 *
 * @since 26.12.2017
 */
public class StringMessageDigestTest {
    private StringMessageDigest stringMessageDigest;
    private String usageName = "name";

    @Before
    public void setUp() throws Exception {
        stringMessageDigest = new HkdfMessageDigest(new byte[32], 12);
    }

    @Test
    public void testDeterminism() throws Exception {
        for (int i = 1; i < 256; i *= 2) {
            String randomKey = Bytes.random(i).encodeHex();
            String out = stringMessageDigest.derive(randomKey, usageName);
            String out2 = stringMessageDigest.derive(randomKey, usageName);
            assertEquals(out, out2);
        }
    }

    @Test
    public void differentUsageShouldNotBeEquals() throws Exception {
        String randomKey = Bytes.random(16).encodeHex();
        assertNotEquals(stringMessageDigest.derive(randomKey, usageName), stringMessageDigest.derive(randomKey, usageName + "2"));
    }

    @Test
    public void differentSaltShouldNotBeEquals() throws Exception {
        StringMessageDigest stringMessageDigest2 = new HkdfMessageDigest(new byte[]{1, 2, 3, 45, 6, 1}, 12);
        String randomKey = Bytes.random(16).encodeHex();
        assertNotEquals(stringMessageDigest.derive(randomKey, usageName), stringMessageDigest2.derive(randomKey, usageName));
    }

    @Test(expected = NullPointerException.class)
    public void nullUsageShouldThrowException() throws Exception {
        stringMessageDigest.derive("", null);
    }

    @Test(expected = NullPointerException.class)
    public void nullKeyShouldThrowException() throws Exception {
        stringMessageDigest.derive(null, usageName);
    }
}
