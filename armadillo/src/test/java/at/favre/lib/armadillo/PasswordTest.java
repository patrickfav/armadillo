package at.favre.lib.armadillo;

import android.content.SharedPreferences;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

public class PasswordTest {

    private static final char[] PASSWORD_1 = "mypass1".toCharArray();
    private static final char[] PASSWORD_2 = "mypass2".toCharArray();

    private SharedPreferences mockPreferences;

    @Before
    public void setup() {
        mockPreferences = new MockSharedPref();
    }

    @After
    public void tearDown() {
        mockPreferences.edit().clear().commit();
    }

    @Test(expected = SecureSharedPreferenceCryptoException.class)
    public void testDifferentPasswords() {
        // Get armadillo instance with PASSWORD_1
        SharedPreferences encryptedPreferences = createArmadillo(mockPreferences, PASSWORD_1).build();
        // Put data
        String key = "key1";
        String value = "value1";
        encryptedPreferences.edit().putString(key, value).commit();
        assertTrue(encryptedPreferences.contains(key));
        assertEquals(value, encryptedPreferences.getString(key, null));
        // Get armadillo instance with PASSWORD_2
        encryptedPreferences = createArmadillo(mockPreferences, PASSWORD_2).build();
        assertTrue(encryptedPreferences.contains(key));
        encryptedPreferences.getString(key, null);
    }

    private Armadillo.Builder createArmadillo(SharedPreferences preferences, char[] password) {
        return Armadillo.create(preferences)
                .encryptionFingerprint(new byte[16])
                .password(password);
    }
}
