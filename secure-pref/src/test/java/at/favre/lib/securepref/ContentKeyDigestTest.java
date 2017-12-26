package at.favre.lib.securepref;

import org.junit.Before;
import org.junit.Test;

import at.favre.lib.bytes.Bytes;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 *
 * @since 26.12.2017
 */
public class ContentKeyDigestTest {
    private ContentKeyDigest contentKeyDigest;
    private String usageName = "name";

    @Before
    public void setUp() throws Exception {
        contentKeyDigest = new HkdfKeyDigest(new byte[32], 12);
    }

    @Test
    public void testDeterminism() throws Exception {
        for (int i = 1; i < 256; i *= 2) {
            String randomKey = Bytes.random(i).encodeHex();
            String out = contentKeyDigest.derive(randomKey, usageName);
            String out2 = contentKeyDigest.derive(randomKey, usageName);
            assertEquals(out, out2);
        }
    }

    @Test
    public void differentUsageShouldNotBeEquals() throws Exception {
        String randomKey = Bytes.random(16).encodeHex();
        assertNotEquals(contentKeyDigest.derive(randomKey, usageName), contentKeyDigest.derive(randomKey, usageName + "2"));
    }

    @Test
    public void differentSaltShouldNotBeEquals() throws Exception {
        ContentKeyDigest contentKeyDigest2 = new HkdfKeyDigest(new byte[]{1, 2, 3, 45, 6, 1}, 12);
        String randomKey = Bytes.random(16).encodeHex();
        assertNotEquals(contentKeyDigest.derive(randomKey, usageName), contentKeyDigest2.derive(randomKey, usageName));
    }

    @Test(expected = NullPointerException.class)
    public void nullUsageShouldThrowException() throws Exception {
        contentKeyDigest.derive("", null);
    }

    @Test(expected = NullPointerException.class)
    public void nullKeyShouldThrowException() throws Exception {
        contentKeyDigest.derive(null, usageName);
    }
}
