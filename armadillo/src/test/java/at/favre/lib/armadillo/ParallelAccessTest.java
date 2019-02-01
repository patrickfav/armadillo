package at.favre.lib.armadillo;

import android.content.SharedPreferences;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import at.favre.lib.bytes.Bytes;

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
        testParallelAccess(createArmadillo(mockPreferences, null).build());
    }

    @Test
    public void testParallelAccessWithPasswordCache() {
        testParallelAccess(createArmadillo(mockPreferences, "secret1234".toCharArray())
            .keyStretchingFunction(new FastKeyStretcher())
            .enableDerivedPasswordCache(true).build());
    }

    private void testParallelAccess(SharedPreferences encryptedPreferences) {
        final String value = Bytes.random(16).encodeHex();
        encryptedPreferences.edit().putString("foo", value).apply();

        Thread thread1 = new Thread() {
            @Override
            public void run() {
                for (int i = 0; i < 2500; ++i) {
                    //System.out.println("1: " + System.nanoTime());
                    assertEquals(value, encryptedPreferences.getString("foo", ""));
                }
            }
        };

        thread1.start();

        Thread thread2 = new Thread() {
            @Override
            public void run() {
                for (int i = 0; i < 2000; ++i) {
                    //System.out.println("2: " + System.nanoTime());
                    assertEquals(value, encryptedPreferences.getString("foo", ""));
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

        assertEquals(value, encryptedPreferences.getString("foo", ""));
    }

    private Armadillo.Builder createArmadillo(SharedPreferences preferences, char[] password) {
        return Armadillo.create(preferences)
            .encryptionFingerprint(new byte[16])
            .password(password);
    }
}
