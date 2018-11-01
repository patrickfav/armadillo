package at.favre.lib.armadillo;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import at.favre.lib.bytes.Bytes;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

public class ByteArrayObfuscatorTest {

    @Test
    public void obfuscateRandom() {
        for (int i = 0; i < 100; i++) {
            testIntern(Bytes.random(32).array());
        }
    }

    @Test
    public void obfuscateVariousLengths() {
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
    public void obfuscateSimpleData() {
        testIntern(Bytes.allocate(1).array());
        testIntern(Bytes.allocate(2).array());
        testIntern(Bytes.allocate(16).array());
        testIntern(Bytes.allocate(32).array());
    }

    private void testIntern(byte[] target) {
        System.out.println("original:   " + Bytes.wrap(target).encodeHex());
        ByteArrayRuntimeObfuscator obfuscator = new ByteArrayRuntimeObfuscator.Default(Bytes.wrap(target).copy().array(), new SecureRandom());

        byte[] unobfuscated = Bytes.wrap(obfuscator.getBytes()).copy().array();
        byte[] unobfuscated2 = Bytes.wrap(obfuscator.getBytes()).copy().array();
        byte[] unobfuscated3 = Bytes.wrap(obfuscator.getBytes()).copy().array();

        System.out.println("deobfuscated: " + Bytes.wrap(unobfuscated).encodeHex());

        assertArrayEquals(target, unobfuscated);
        assertArrayEquals(unobfuscated, unobfuscated2);
        assertArrayEquals(unobfuscated2, unobfuscated3);

        obfuscator.wipe();

        assertFalse(Arrays.equals(obfuscator.getBytes(), target));
        assertFalse(Arrays.equals(obfuscator.getBytes(), unobfuscated));
        assertFalse(Arrays.equals(obfuscator.getBytes(), unobfuscated2));
    }
}
