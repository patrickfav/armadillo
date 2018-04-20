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

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public abstract class ASecureSharedPreferencesTest {
    private static final String DEFAULT_PREF_NAME = "test-prefs";
    SharedPreferences preferences;

    @Before
    public void setup() {
        try {
            preferences = create(DEFAULT_PREF_NAME, null).build();
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

    @Test
    public void simpleGetStringApply() throws Exception {
        String content = Bytes.random(16).encodeBase64();
        preferences.edit().putString("d", content).apply();
        assertEquals(content, preferences.getString("d", null));
    }

    private String putAndTestString(SharedPreferences preferences, String key, int length) {
        String content = Bytes.random(length).encodeBase64();
        preferences.edit().putString(key, content).commit();
        assertTrue(preferences.contains(key));
        assertEquals(content, preferences.getString(key, null));
        return content;
    }

    @Test
    public void simpleGetInt() throws Exception {
        int content = 3782633;
        preferences.edit().putInt("int", content).commit();
        assertTrue(preferences.contains("int"));
        assertEquals(content, preferences.getInt("int", 0));
    }

    @Test
    public void simpleGetLong() throws Exception {
        long content = 3782633654323456L;
        preferences.edit().putLong("long", content).commit();
        assertTrue(preferences.contains("long"));
        assertEquals(content, preferences.getLong("long", 0));
    }

    @Test
    public void simpleGetFloat() throws Exception {
        float content = 728.1891f;
        preferences.edit().putFloat("float", content).commit();
        assertTrue(preferences.contains("float"));
        assertEquals(content, preferences.getFloat("float", 0), 0.001);
    }

    @Test
    public void simpleGetBoolean() throws Exception {
        preferences.edit().putBoolean("boolean", true).commit();
        assertTrue(preferences.contains("boolean"));
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
        assertTrue(preferences.contains("stringSet" + count));
        assertEquals(set, preferences.getStringSet("stringSet" + count, null));
    }

    @Test
    public void testGetDefaults() throws Exception {
        assertNull(preferences.getString("s", null));
        assertNull(preferences.getStringSet("s", null));
        assertFalse(preferences.getBoolean("s", false));
        assertEquals(2, preferences.getInt("s", 2));
        assertEquals(2, preferences.getLong("s", 2));
        assertEquals(2f, preferences.getFloat("s", 2f), 0.0001);
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
    public void testPutNullString() {
        String id = "testPutNullString";
        putAndTestString(preferences, id, new Random().nextInt(32) + 1);
        preferences.edit().putString(id, null).apply();
        assertFalse(preferences.contains(id));
    }

    @Test
    public void testPutNullStringSet() {
        String id = "testPutNullStringSet";
        addStringSet(preferences, 8);
        preferences.edit().putStringSet(id, null).apply();
        assertFalse(preferences.contains(id));
    }

    @Test
    public void testClear() {
        int count = 10;
        for (int i = 0; i < count; i++) {
            putAndTestString(preferences, "string" + i, new Random().nextInt(32) + 1);
        }

        assertFalse(preferences.getAll().isEmpty());
        preferences.edit().clear().commit();
        assertTrue(preferences.getAll().isEmpty());

        String newContent = putAndTestString(preferences, "new", new Random().nextInt(32) + 1);
        assertFalse(preferences.getAll().isEmpty());

        preferences = create(DEFAULT_PREF_NAME, null).build();
        assertEquals(newContent, preferences.getString("new", null));
    }

    @Test
    public void testInitializeTwice() throws Exception {
        SharedPreferences sharedPreferences = create("init", null).build();
        putAndTestString(sharedPreferences, "s", 12);
        sharedPreferences = create("init", null).build();
        putAndTestString(sharedPreferences, "s2", 24);
    }

    @Test
    public void testContainsAfterReinitialization() throws Exception {
        SharedPreferences sharedPreferences = create("twice", null).build();
        String t = putAndTestString(sharedPreferences, "s", 12);
        sharedPreferences = create("twice", null).build();
        assertEquals(t, sharedPreferences.getString("s", null));
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
        preferenceSmokeTest(create("fingerprint2", null)
                .encryptionFingerprint(() -> new byte[16]).build());
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
        preferenceSmokeTest(create("secureRandom", null)
                .secureRandom(new SecureRandom()).build());
    }

    @Test
    public void testEncryptionStrength() throws Exception {
        preferenceSmokeTest(create("secureRandom", null)
                .encryptionKeyStrength(AuthenticatedEncryption.STRENGTH_HIGH).build());
    }

    @Test
    public void testProvider() throws Exception {
        preferenceSmokeTest(create("provider", null)
                .securityProvider(null).build());
    }

    @Test
    public void testWithNoObfuscation() throws Exception {
        preferenceSmokeTest(create("obfuscate", null)
                .dataObfuscatorFactory(new NoObfuscator.Factory()).build());
    }

    @Test
    public void testSetEncryption() throws Exception {
        preferenceSmokeTest(create("enc", null)
                .symmetricEncryption(new AesGcmEncryption()).build());
    }

    @Test
    public void testRecoveryPolicy() throws Exception {
        preferenceSmokeTest(create("recovery", null)
                .recoveryPolicy(true, true).build());
        preferenceSmokeTest(create("recovery", null)
                .recoveryPolicy(new RecoveryPolicy.Default(true, true)).build());
    }

    @Test
    public void testCustomProtocolVersion() throws Exception {
        preferenceSmokeTest(create("protocol", null)
                .cryptoProtocolVersion(14221).build());
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
