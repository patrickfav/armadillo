package at.favre.lib.armadillo;

import android.content.SharedPreferences;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class ParallelAccessTest {

    private SharedPreferences mockPreferences;

    @Before
    public void setup() {
        mockPreferences = new MockSharedPref();
    }

    @After
    public void tearDown() {
        mockPreferences.edit().clear().commit();
    }

    @Test
    public void testParallelAccess() {
        SharedPreferences encryptedPreferences = createArmadillo(mockPreferences, null, false).build();

        encryptedPreferences.edit().putString("foo", "D62A13F997F350B6E17A6B41AA477200").apply();

        Thread thread1 = new Thread() {
            @Override
            public void run() {
                for (int i = 0; i < 2500; ++i) {
                    assertEquals("D62A13F997F350B6E17A6B41AA477200", encryptedPreferences.getString("foo", ""));
                }
            }
        };

        thread1.start();

        Thread thread2 = new Thread() {
            @Override
            public void run() {
                for (int i = 0; i < 2000; ++i) {
                    assertEquals("D62A13F997F350B6E17A6B41AA477200", encryptedPreferences.getString("foo", ""));
                }
            }
        };

        thread2.start();
        
        try {
            thread1.join();
            thread2.join();
        } catch (InterruptedException ignored) {
            fail();
        }

        assertEquals("D62A13F997F350B6E17A6B41AA477200", encryptedPreferences.getString("foo", ""));
    }

    private Armadillo.Builder createArmadillo(SharedPreferences preferences, char[] password, boolean validatePassword) {
        return Armadillo.create(preferences)
                .encryptionFingerprint(new byte[16])
                .password(password)
                .supportVerifyPassword(validatePassword);
    }
}
