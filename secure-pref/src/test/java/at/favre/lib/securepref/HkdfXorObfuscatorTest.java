package at.favre.lib.securepref;

import org.junit.Before;
import org.junit.Test;

import at.favre.lib.bytes.Bytes;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class HkdfXorObfuscatorTest {

    private DataObfuscator obfuscator;

    @Before
    public void setUp() throws Exception {
        obfuscator = new HkdfXorObfuscator(Bytes.random(16).array());
    }

    @Test
    public void obfuscateRandom() throws Exception {
        for (int i = 0; i < 100; i++) {
            testIntern(Bytes.random(32).array());
        }
    }

    @Test
    public void obfuscateVariousLengths() throws Exception {
        testIntern(Bytes.random(1).array());
        testIntern(Bytes.random(2).array());
        testIntern(Bytes.random(3).array());
        testIntern(Bytes.random(3).array());
        testIntern(Bytes.random(16).array());
        testIntern(Bytes.random(23).array());
        testIntern(Bytes.random(24).array());
        testIntern(Bytes.random(25).array());
        testIntern(Bytes.random(32).array());
        testIntern(Bytes.random(512).array());
    }

    @Test
    public void obfuscateSimpleData() throws Exception {
        testIntern(Bytes.allocate(1).array());
        testIntern(Bytes.allocate(2).array());
        testIntern(Bytes.allocate(16).array());
        testIntern(Bytes.allocate(32).array());
    }

    private void testIntern(byte[] target) {
        byte[] originalCopy = Bytes.wrap(target).copy().array();
        obfuscator.obfuscate(target);

        System.out.println("original:   " + Bytes.wrap(originalCopy).encodeHex());
        System.out.println("obfuscated: " + Bytes.wrap(target).encodeHex());

        assertEquals(target.length, originalCopy.length);
        assertFalse(Bytes.wrap(target).equals(originalCopy));

        obfuscator.deobfuscate(target);
        assertTrue(Bytes.wrap(target).equals(originalCopy));
    }

}
