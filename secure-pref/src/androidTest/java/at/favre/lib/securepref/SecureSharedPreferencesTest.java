package at.favre.lib.securepref;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import at.favre.lib.bytes.Bytes;

import static org.junit.Assert.assertEquals;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class SecureSharedPreferencesTest {

    private SharedPreferences preferences;

    @Before
    public void setup() {
        preferences = create("test-prefs", null);
    }

    @After
    public void tearDown() {
        preferences.edit().clear().commit();
    }

    @NonNull
    private SecureSharedPreferences create(String name, char[] pw) {
        Context appContext = InstrumentationRegistry.getTargetContext();
        SecureRandom secureRandom = new SecureRandom();
        EncryptionFingerprint fingerprint = EncryptionFingerprintFactory.create(appContext, null);
        return new SecureSharedPreferences(
                appContext,
                name,
                new DefaultEncryptionProtocol(
                        new AesGcmEncryption(secureRandom), new PBKDF2KeyStretcher(),
                        SymmetricEncryption.STRENGTH_HIGH,
                        fingerprint, BuildConfig.PREF_SALT), pw, secureRandom);
    }

    @Test
    public void simpleMultipleStringGet() throws Exception {
        SecureSharedPreferences preferences = create("manytest", null);
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 100; j++) {
                String content = "testäI/_²~" + Bytes.random(64 + j).encodeHex();
                preferences.edit().putString("k" + j, content).apply();
                assertEquals(content, preferences.getString("k" + j, null));
            }
        }
    }

    @Test
    public void simpleGetString() throws Exception {
        String content = "testäI/_²~";
        preferences.edit().putString("string", content).apply();
        assertEquals(content, preferences.getString("string", null));
    }

    @Test
    public void simpleGetInt() throws Exception {
        int content = 3782633;
        preferences.edit().putInt("int", content).apply();
        assertEquals(content, preferences.getInt("int", 0));
    }

    @Test
    public void simpleGetLong() throws Exception {
        long content = 3782633654323456L;
        preferences.edit().putLong("long", content).apply();
        assertEquals(content, preferences.getLong("long", 0));
    }

    @Test
    public void simpleGetFloat() throws Exception {
        float content = 728.1891f;
        preferences.edit().putFloat("float", content).apply();
        assertEquals(content, preferences.getFloat("float", 0), 0.001);
    }

    @Test
    public void simpleGetBoolean() throws Exception {
        preferences.edit().putBoolean("boolean", true).apply();
        assertEquals(true, preferences.getBoolean("boolean", false));

        preferences.edit().putBoolean("boolean2", false).apply();
        assertEquals(false, preferences.getBoolean("boolean2", true));
    }

    @Test
    public void simpleGetStringSet() throws Exception {
        Set<String> set = new HashSet<>(7);
        for (int i = 0; i < 7; i++) {
            set.add("input" + i);
        }

        preferences.edit().putStringSet("stringSet", set).apply();
        assertEquals(set, preferences.getStringSet("stringSet", null));
    }

    @Test
    public void simpleStringGetWithPassword() throws Exception {
        SecureSharedPreferences preferences = create("withPw", "superSecret".toCharArray());
        String content = "testäI/_²~" + Bytes.random(64).encodeHex();
        preferences.edit().putString("k", content).apply();
        assertEquals(content, preferences.getString("k", null));
    }
}
