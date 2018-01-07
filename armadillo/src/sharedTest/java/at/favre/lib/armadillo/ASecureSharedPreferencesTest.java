package at.favre.lib.armadillo;

import android.content.SharedPreferences;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import at.favre.lib.bytes.Bytes;

import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public abstract class ASecureSharedPreferencesTest {

    private SharedPreferences preferences;

    @Before
    public void setup() {
        try {
            preferences = create("test-prefs", null).build();
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    @After
    public void tearDown() {
        preferences.edit().clear().commit();
    }

    protected abstract Armadillo.Builder create(String name, char[] pw);

    @Test
    public void simpleMultipleStringGet() throws Exception {
        SharedPreferences preferences = create("manytest", null).build();
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 100; j++) {
                String content = "testäI/_²~" + Bytes.random(64 + j).encodeHex();
                preferences.edit().putString("k" + j, content).commit();
                assertEquals(content, preferences.getString("k" + j, null));
            }
        }
    }

    @Test
    public void simpleGetString() throws Exception {
        putAndTestString(preferences, "string1", 1);
        putAndTestString(preferences, "string2", 16);
        putAndTestString(preferences, "string3", 200);
    }

    private void putAndTestString(SharedPreferences preferences, String key, int length) {
        String content = Bytes.random(length).encodeBase64();
        preferences.edit().putString(key, content).commit();
        assertEquals(content, preferences.getString(key, null));
    }

    @Test
    public void simpleGetInt() throws Exception {
        int content = 3782633;
        preferences.edit().putInt("int", content).commit();
        assertEquals(content, preferences.getInt("int", 0));
    }

    @Test
    public void simpleGetLong() throws Exception {
        long content = 3782633654323456L;
        preferences.edit().putLong("long", content).commit();
        assertEquals(content, preferences.getLong("long", 0));
    }

    @Test
    public void simpleGetFloat() throws Exception {
        float content = 728.1891f;
        preferences.edit().putFloat("float", content).commit();
        assertEquals(content, preferences.getFloat("float", 0), 0.001);
    }

    @Test
    public void simpleGetBoolean() throws Exception {
        preferences.edit().putBoolean("boolean", true).commit();
        assertEquals(true, preferences.getBoolean("boolean", false));

        preferences.edit().putBoolean("boolean2", false).commit();
        assertEquals(false, preferences.getBoolean("boolean2", true));
    }

    @Test
    public void simpleGetStringSet() throws Exception {
        addStringSet(preferences, 1);
        addStringSet(preferences, 7);
        addStringSet(preferences, 128);
    }

    private void addStringSet(SharedPreferences preferences, int count) {
        Set<String> set = new HashSet<>(count);
        for (int i = 0; i < count; i++) {
            set.add(Bytes.random(32).encodeBase36() + "input" + i);
        }

        preferences.edit().putStringSet("stringSet" + count, set).commit();
        assertEquals(set, preferences.getStringSet("stringSet" + count, null));
    }

    @Test
    public void testRemove() {
        int count = 10;
        for (int i = 0; i < count; i++) {
            putAndTestString(preferences, "string" + i, new Random().nextInt(32) + 1);
        }

        assertTrue(preferences.getAll().size() >= count);

        for (int i = 0; i < count; i++) {
            preferences.edit().remove("string" + i).commit();
            assertNull(preferences.getString("string" + i, null));
        }
    }

    @Test
    public void testIntializeTwice() throws Exception {
        SharedPreferences sharedPreferences = create("init", null).build();
        putAndTestString(sharedPreferences, "s", 12);
        sharedPreferences = create("init", null).build();
        putAndTestString(sharedPreferences, "s2", 24);
    }

    @Test
    public void simpleStringGetWithPkdf2Password() throws Exception {
        preferenceSmokeTest(create("withPw", "superSecret".toCharArray())
            .keyStretchingFunction(new PBKDF2KeyStretcher(1000, null)).build());
    }

    @Test
    public void simpleStringGetWithBcryptPassword() throws Exception {
        preferenceSmokeTest(create("withPw", "superSecret".toCharArray())
            .keyStretchingFunction(new BcryptKeyStretcher(8)).build());
    }

    @Test
    public void simpleStringGetWithFastKDF() throws Exception {
        preferenceSmokeTest(create("withPw", "superSecret".toCharArray())
            .keyStretchingFunction(new FastKeyStretcher()).build());
    }

    @Test
    public void testWithCompression() throws Exception {
        preferenceSmokeTest(create("compressed", null).compress().build());
    }

    @Test
    public void testWithDifferentFingerprint() throws Exception {
        preferenceSmokeTest(create("fingerprint", null)
            .encryptionFingerprint(Bytes.random(16).array()).build());
    }

    @Test
    public void testWithDifferentContentDigest() throws Exception {
        preferenceSmokeTest(create("contentDigest1", null)
            .contentKeyDigest(8).build());
        preferenceSmokeTest(create("contentDigest2", null)
            .contentKeyDigest(Bytes.random(16).array()).build());
    }

    @Test
    public void testWithSecureRandom() throws Exception {
        preferenceSmokeTest(create("fingerprint", null)
            .secureRandom(new SecureRandom()).build());
    }

    @Test
    public void testWithNoObfuscation() throws Exception {
        preferenceSmokeTest(create("fingerprint", null)
            .dataObfuscatorFactory(new NoObfuscator.Factory()).build());
    }

    void preferenceSmokeTest(SharedPreferences preferences) {
        putAndTestString(preferences, "string", new Random().nextInt(500) + 1);
        assertNull(preferences.getString("string2", null));

        long contentLong = new Random().nextLong();
        preferences.edit().putLong("long", contentLong).commit();
        assertEquals(contentLong, preferences.getLong("long", 0));

        float contentFloat = new Random().nextFloat();
        preferences.edit().putFloat("float", contentFloat).commit();
        assertEquals(contentFloat, preferences.getFloat("float", 0), 0.001);

        boolean contentBoolean = new Random().nextBoolean();
        preferences.edit().putBoolean("boolean", contentBoolean).commit();
        assertEquals(contentBoolean, preferences.getBoolean("boolean", !contentBoolean));

        addStringSet(preferences, new Random().nextInt(31) + 1);

        preferences.edit().remove("string").commit();
        assertNull(preferences.getString("string", null));

        preferences.edit().remove("float").commit();
        assertEquals(-1, preferences.getFloat("float", -1), 0.00001);
    }
}
