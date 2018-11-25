package at.favre.lib.armadillo;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import at.favre.lib.bytes.Bytes;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNull;

public class DerivedPasswordCacheTest {

    private DerivedPasswordCache cache;
    private char[] pw;
    private byte[] salt;

    @Before
    public void setUp() {
        cache = new DerivedPasswordCache.Default(true, new SecureRandom());
        pw = Bytes.random(12).encodeBase64Url().toCharArray();
        salt = Bytes.random(16).array();
    }

    @Test
    public void get() {
        Bytes val = Bytes.random(128);
        cache.put(salt, pw, val.copy().array());
        assertEquals(val, Bytes.wrapNullSafe(cache.get(salt, pw)));
        assertEquals(val, Bytes.wrapNullSafe(cache.get(salt, pw)));

        cache.wipe();

        assertNull(cache.get(salt, pw));
    }

    @Test
    public void getWhileDisabled() {
        cache = new DerivedPasswordCache.Default(false, new SecureRandom());
        cache.put(salt, pw, Bytes.random(128).array());
        assertNull(cache.get(salt, pw));
    }
}
