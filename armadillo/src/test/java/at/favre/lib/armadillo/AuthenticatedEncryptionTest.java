package at.favre.lib.armadillo;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;

import at.favre.lib.bytes.Bytes;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class AuthenticatedEncryptionTest {
    private static final int TEST_LOOP_COUNT = 10;
    private AuthenticatedEncryption authenticatedEncryption;

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { new AesGcmEncryption(new SecureRandom()) },
                { new AesCbcEncryption(new SecureRandom()) }
        });
    }

    public AuthenticatedEncryptionTest(AuthenticatedEncryption authenticatedEncryption) {
        this.authenticatedEncryption = authenticatedEncryption;
    }

    @Test
    public void encryptNullArrays() throws Exception {
        testEncryptDecrypt(new byte[1], Bytes.random(16).array(), null);
        testEncryptDecrypt(new byte[2], Bytes.random(16).array(), null);
        testEncryptDecrypt(new byte[3], Bytes.random(16).array(), null);
        testEncryptDecrypt(new byte[15], Bytes.random(16).array(), null);
        testEncryptDecrypt(new byte[16], Bytes.random(16).array(), null);
        testEncryptDecrypt(new byte[17], Bytes.random(16).array(), null);
        testEncryptDecrypt(new byte[32], Bytes.random(16).array(), null);
    }

    @Test
    public void encryptMultiple128BitKey() throws Exception {
        for (int j = 0; j < TEST_LOOP_COUNT ; j++) {
            testEncryptDecrypt(Bytes.random(1).array(), Bytes.random(16).array(), null);
            testEncryptDecrypt(Bytes.random(2).array(), Bytes.random(16).array(), null);
            testEncryptDecrypt(Bytes.random(16).array(), Bytes.random(16).array(), null);
            testEncryptDecrypt(Bytes.random(24).array(), Bytes.random(16).array(), null);
            testEncryptDecrypt(Bytes.random(32).array(), Bytes.random(16).array(), null);
            testEncryptDecrypt(Bytes.random(64).array(), Bytes.random(16).array(), null);
            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(16).array(), null);

            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(16).array(), Bytes.random(1).array());
            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(16).array(), Bytes.random(4).array());
            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(16).array(), Bytes.random(16).array());
            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(16).array(), Bytes.random(32).array());
            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(16).array(), Bytes.random(128).array());
        }
    }

    @Test
    public void encryptMultiple256BitKey() throws Exception {
        for (int j = 0; j < TEST_LOOP_COUNT; j++) {
            testEncryptDecrypt(Bytes.random(1).array(), Bytes.random(32).array(), null);
            testEncryptDecrypt(Bytes.random(2).array(), Bytes.random(32).array(), null);
            testEncryptDecrypt(Bytes.random(16).array(), Bytes.random(32).array(), null);
            testEncryptDecrypt(Bytes.random(24).array(), Bytes.random(32).array(), null);
            testEncryptDecrypt(Bytes.random(32).array(), Bytes.random(32).array(), null);
            testEncryptDecrypt(Bytes.random(64).array(), Bytes.random(32).array(), null);
            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(32).array(), null);
        }
    }

    @Test
    public void encryptMultipleWithAAD() throws Exception {
        for (int j = 0; j < TEST_LOOP_COUNT; j++) {
            testEncryptDecrypt(Bytes.random(1).array(), Bytes.random(16).array(), Bytes.random(1).array());
            testEncryptDecrypt(Bytes.random(1).array(), Bytes.random(16).array(), Bytes.random(4).array());
            testEncryptDecrypt(Bytes.random(1).array(), Bytes.random(16).array(), Bytes.random(16).array());
            testEncryptDecrypt(Bytes.random(1).array(), Bytes.random(16).array(), Bytes.random(32).array());
            testEncryptDecrypt(Bytes.random(1).array(), Bytes.random(16).array(), Bytes.random(128).array());

            testEncryptDecrypt(Bytes.random(16).array(), Bytes.random(16).array(), Bytes.random(1).array());
            testEncryptDecrypt(Bytes.random(16).array(), Bytes.random(16).array(), Bytes.random(4).array());
            testEncryptDecrypt(Bytes.random(16).array(), Bytes.random(16).array(), Bytes.random(16).array());
            testEncryptDecrypt(Bytes.random(16).array(), Bytes.random(16).array(), Bytes.random(32).array());
            testEncryptDecrypt(Bytes.random(16).array(), Bytes.random(16).array(), Bytes.random(128).array());

            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(16).array(), Bytes.random(16).array());
            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(16).array(), Bytes.random(32).array());
            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(16).array(), Bytes.random(128).array());

            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(32).array(), Bytes.random(16).array());
            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(32).array(), Bytes.random(32).array());
            testEncryptDecrypt(Bytes.random(128).array(), Bytes.random(32).array(), Bytes.random(128).array());
        }
    }

    private void testEncryptDecrypt(byte[] content, byte[] key, byte[] aad) throws AuthenticatedEncryptionException {
        byte[] encrypted = authenticatedEncryption.encrypt(key, content, aad);
        assertTrue(encrypted.length >= content.length);
        assertFalse(Bytes.wrap(encrypted).equals(content));

        System.out.println("content:   " + Bytes.wrap(content).encodeHex());
        System.out.println("encrypted: " + Bytes.wrap(encrypted).encodeHex());

        byte[] decrypt = authenticatedEncryption.decrypt(key, encrypted, aad);
        assertTrue(Bytes.wrap(decrypt).equals(content));
    }
}
