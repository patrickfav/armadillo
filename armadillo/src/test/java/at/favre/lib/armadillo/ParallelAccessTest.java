package at.favre.lib.armadillo;

import android.content.SharedPreferences;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

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

        encryptedPreferences.edit().putString("foo", "1").apply();

        long start = System.currentTimeMillis();
        Thread thread1 = new Thread() {
            @Override
            public void run() {
                for (int i = 0; i < 100; ++i) {
                    encryptedPreferences.getString("foo", "");
                }
            }
        };

        thread1.start();

        Thread thread2 = new Thread() {
            @Override
            public void run() {
                for (int i = 0; i < 100; ++i) {
                    encryptedPreferences.getString("foo", "");
                }
            }
        };

        thread2.start();
        
        try {
            thread1.join();
            thread2.join();
        } catch (InterruptedException ignored) {
        }

        assertEquals("1", encryptedPreferences.getString("foo", ""));
    }

    private Armadillo.Builder createArmadillo(SharedPreferences preferences, char[] password, boolean validatePassword) {
        return Armadillo.create(preferences)
                .encryptionFingerprint(new byte[16])
                .password(password)
                .supportVerifyPassword(validatePassword);
    }
}
