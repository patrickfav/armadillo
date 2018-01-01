package at.favre.lib.armadillo;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import at.favre.lib.bytes.Bytes;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuthenticatedEncryptionTest {
    private AuthenticatedEncryption authenticatedEncryption;

    @Before
    public void setUp() throws Exception {
        authenticatedEncryption = new AesGcmEncryption(new SecureRandom());
    }

    @Test
    public void encryptNullArrays() throws Exception {
        testEncryptDecrypt(new byte[1], Bytes.random(16).array());
        testEncryptDecrypt(new byte[2], Bytes.random(16).array());
        testEncryptDecrypt(new byte[3], Bytes.random(16).array());
        testEncryptDecrypt(new byte[15], Bytes.random(16).array());
        testEncryptDecrypt(new byte[16], Bytes.random(16).array());
        testEncryptDecrypt(new byte[17], Bytes.random(16).array());
        testEncryptDecrypt(new byte[32], Bytes.random(16).array());
    }

    @Test
    public void encryptMultiple() throws Exception {
        for (int j = 0; j < 20; j++) {
            testEncryptDecrypt(Bytes.random(1).array(), Bytes.random(16).array());
            testEncryptDecrypt(Bytes.random(2).array(), Bytes.random(16).array());
            testEncryptDecrypt(Bytes.random(16).array(), Bytes.random(16).array());
            testEncryptDecrypt(Bytes.random(24).array(), Bytes.random(16).array());
            testEncryptDecrypt(Bytes.random(32).array(), Bytes.random(16).array());
            testEncryptDecrypt(Bytes.random(64).array(), Bytes.random(16).array());
            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(16).array());
        }
    }

    private void testEncryptDecrypt(byte[] content, byte[] key) throws AuthenticatedEncryptionException {
        byte[] encrypted = authenticatedEncryption.encrypt(key, content, null);
        assertTrue(encrypted.length >= content.length);
        assertFalse(Bytes.wrap(encrypted).equals(content));

        System.out.println("content:   " + Bytes.wrap(content).encodeHex());
        System.out.println("encrypted: " + Bytes.wrap(encrypted).encodeHex());

        byte[] decrypt = authenticatedEncryption.decrypt(key, encrypted, null);
        assertTrue(Bytes.wrap(decrypt).equals(content));
    }

}
