package at.favre.lib.armadillo;

import android.content.SharedPreferences;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static junit.framework.Assert.assertFalse;
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
        SharedPreferences encryptedPreferences = createArmadillo(mockPreferences, PASSWORD_1, false).build();
        // Put data
        String key = "key1";
        String value = "value1";
        encryptedPreferences.edit().putString(key, value).commit();
        assertTrue(encryptedPreferences.contains(key));
        assertEquals(value, encryptedPreferences.getString(key, null));
        // Get armadillo instance with PASSWORD_2
        encryptedPreferences = createArmadillo(mockPreferences, PASSWORD_2, false).build();
        assertTrue(encryptedPreferences.contains(key));
        encryptedPreferences.getString(key, null);
    }

    @Test
    public void testPasswordValidation() {
        // Init armadillo with PASSWORD_1
        ArmadilloSharedPreferences encryptedPreferences = createArmadillo(mockPreferences, PASSWORD_1, true).build();
        // Validate password
        assertTrue(encryptedPreferences.isValidPassword());
        // Get armadillo with PASSWORD_2 -> incorrect pass
        encryptedPreferences = createArmadillo(mockPreferences, PASSWORD_2, true).build();
        assertFalse(encryptedPreferences.isValidPassword());
        // Get armadillo with PASSWORD_1 -> correct pass
        encryptedPreferences = createArmadillo(mockPreferences, PASSWORD_1, true).build();
        assertTrue(encryptedPreferences.isValidPassword());
    }

    @Test
    public void testPasswordValidationPasswordChanged() {
        // Init armadillo with PASSWORD_1
        ArmadilloSharedPreferences encryptedPreferences = createArmadillo(mockPreferences, PASSWORD_1, true).build();
        // Validate password
        assertTrue(encryptedPreferences.isValidPassword());
        // Change password to PASSWORD_2
        encryptedPreferences.changePassword(PASSWORD_2);
        // Get armadillo with PASSWORD_1 -> incorrect pass
        encryptedPreferences = createArmadillo(mockPreferences, PASSWORD_1, true).build();
        assertFalse(encryptedPreferences.isValidPassword());
        // Get armadillo with PASSWORD_2 -> correct pass
        encryptedPreferences = createArmadillo(mockPreferences, PASSWORD_2, true).build();
        assertTrue(encryptedPreferences.isValidPassword());
    }

    private Armadillo.Builder createArmadillo(SharedPreferences preferences, char[] password, boolean validatePassword) {
        return Armadillo.create(preferences)
                .encryptionFingerprint(new byte[16])
                .password(password)
                .supportVerifyPassword(validatePassword);
    }
}
