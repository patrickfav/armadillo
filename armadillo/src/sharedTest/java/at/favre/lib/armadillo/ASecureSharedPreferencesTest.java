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
import static junit.framework.Assert.fail;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assume.assumeFalse;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@SuppressWarnings("deprecation")
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

    protected abstract boolean isKitKatOrBelow();

    @Test
    public void simpleMultipleStringGet() {
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
    public void simpleGetString() {
        putAndTestString(preferences, "string1", 1);
        putAndTestString(preferences, "string2", 16);
        putAndTestString(preferences, "string3", 200);
    }

    @Test
    public void simpleGetStringApply() {
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
    public void simpleGetInt() {
        int content = 3782633;
        preferences.edit().putInt("int", content).commit();
        assertTrue(preferences.contains("int"));
        assertEquals(content, preferences.getInt("int", 0));
    }

    @Test
    public void simpleGetLong() {
        long content = 3782633654323456L;
        preferences.edit().putLong("long", content).commit();
        assertTrue(preferences.contains("long"));
        assertEquals(content, preferences.getLong("long", 0));
    }

    @Test
    public void simpleGetFloat() {
        float content = 728.1891f;
        preferences.edit().putFloat("float", content).commit();
        assertTrue(preferences.contains("float"));
        assertEquals(content, preferences.getFloat("float", 0), 0.001);
    }

    @Test
    public void simpleGetBoolean() {
        preferences.edit().putBoolean("boolean", true).commit();
        assertTrue(preferences.contains("boolean"));
        assertTrue(preferences.getBoolean("boolean", false));

        preferences.edit().putBoolean("boolean2", false).commit();
        assertFalse(preferences.getBoolean("boolean2", true));
    }

    @Test
    public void simpleGetStringSet() {
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
    public void testGetDefaults() {
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
    public void testInitializeTwice() {
        SharedPreferences sharedPreferences = create("init", null).build();
        putAndTestString(sharedPreferences, "s", 12);
        sharedPreferences = create("init", null).build();
        putAndTestString(sharedPreferences, "s2", 24);
    }

    @Test
    public void testContainsAfterReinitialization() {
        SharedPreferences sharedPreferences = create("twice", null).build();
        String t = putAndTestString(sharedPreferences, "s", 12);
        sharedPreferences = create("twice", null).build();
        assertEquals(t, sharedPreferences.getString("s", null));
        putAndTestString(sharedPreferences, "s2", 24);
    }

    @Test
    public void simpleStringGetWithPkdf2Password() {
        preferenceSmokeTest(create("withPw", "superSecret".toCharArray())
            .keyStretchingFunction(new PBKDF2KeyStretcher(1000, null)).build());
    }

    @Test
    public void simpleStringGetWithBcryptPassword() {
        preferenceSmokeTest(create("withPw", "superSecret".toCharArray())
            .keyStretchingFunction(new ArmadilloBcryptKeyStretcher(7)).build());
    }

    @Test
    public void simpleStringGetWithBrokenBcryptPassword() {
        preferenceSmokeTest(create("withPw", "superSecret".toCharArray())
            .keyStretchingFunction(new BrokenBcryptKeyStretcher(6)).build());
    }

    @Test
    public void simpleStringGetWithFastKDF() {
        preferenceSmokeTest(create("withPw", "superSecret".toCharArray())
            .keyStretchingFunction(new FastKeyStretcher()).build());
    }

    @Test
    public void testWithCompression() {
        preferenceSmokeTest(create("compressed", null).compress().build());
    }

    @Test
    public void testWithDifferentFingerprint() {
        preferenceSmokeTest(create("fingerprint", null)
            .encryptionFingerprint(Bytes.random(16).array()).build());
        preferenceSmokeTest(create("fingerprint2", null)
            .encryptionFingerprint(() -> new byte[16]).build());
    }

    @Test
    public void testWithDifferentContentDigest() {
        preferenceSmokeTest(create("contentDigest1", null)
            .contentKeyDigest(8).build());
        preferenceSmokeTest(create("contentDigest2", null)
            .contentKeyDigest(Bytes.random(16).array()).build());
    }

    @Test
    public void testWithSecureRandom() {
        preferenceSmokeTest(create("secureRandom", null)
            .secureRandom(new SecureRandom()).build());
    }

    @Test
    public void testEncryptionStrength() {
        preferenceSmokeTest(create("secureRandom", null)
            .encryptionKeyStrength(AuthenticatedEncryption.STRENGTH_HIGH).build());
    }

    @Test
    public void testProvider() {
        preferenceSmokeTest(create("provider", null)
            .securityProvider(null).build());
    }

    @Test
    public void testWithNoObfuscation() {
        preferenceSmokeTest(create("obfuscate", null)
            .dataObfuscatorFactory(new NoObfuscator.Factory()).build());
    }

    @Test
    public void testSetEncryption() {
        assumeFalse("test not supported on kitkat devices", isKitKatOrBelow());

        preferenceSmokeTest(create("enc", null)
            .symmetricEncryption(new AesGcmEncryption()).build());
    }

    @Test
    public void testRecoveryPolicy() {
        preferenceSmokeTest(create("recovery", null)
            .recoveryPolicy(true, true).build());
        preferenceSmokeTest(create("recovery", null)
            .recoveryPolicy(new RecoveryPolicy.Default(true, true)).build());
    }

    @Test
    public void testCustomProtocolVersion() {
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

    @Test
    public void testChangePassword() {
        testChangePassword("testChangePassword", "pw1".toCharArray(), "pw2".toCharArray());
    }

    @Test
    public void testChangePasswordFromNullPassword() {
        testChangePassword("testChangePasswordFromNullPassword", null, "pw2".toCharArray());
    }

    @Test
    public void testChangePasswordToNullPassword() {
        testChangePassword("testChangePasswordToNullPassword", "pw1".toCharArray(), null);
    }

    @Test
    public void testChangePasswordFromEmptyPassword() {
        testChangePassword("testChangePasswordFromEmptyPassword", "".toCharArray(), "pw2".toCharArray());
    }

    @Test
    public void testChangePasswordToEmptyPassword() {
        testChangePassword("testChangePasswordToEmptyPassword", "pw1".toCharArray(), "".toCharArray());
    }

    private void testChangePassword(String name, char[] currentPassword, char[] newPassword) {
        Set<String> testSet = new HashSet<>();
        testSet.add("t1");
        testSet.add("t2");
        testSet.add("t3");

        // open new shared pref and add some data
        ArmadilloSharedPreferences pref = create(name, clonePassword(currentPassword))
                .keyStretchingFunction(new FastKeyStretcher()).build();
        pref.edit().putString("k1", "string1").putInt("k2", 2).putStringSet("set", testSet)
                .putBoolean("k3", true).commit();
        pref.close();

        // open again and check if can be used
        pref = create(name, clonePassword(currentPassword))
                .keyStretchingFunction(new FastKeyStretcher()).build();
        assertEquals("string1", pref.getString("k1", null));
        assertEquals(2, pref.getInt("k2", 0));
        assertTrue(pref.getBoolean("k3", false));
        assertEquals(testSet, pref.getStringSet("set", null));
        pref.close();

        // open with old pw and change to new one, all the values should be accessible
        pref = create(name, clonePassword(currentPassword))
                .keyStretchingFunction(new FastKeyStretcher()).build();
        pref.changePassword(clonePassword(newPassword));
        assertEquals("string1", pref.getString("k1", null));
        assertEquals(2, pref.getInt("k2", 0));
        assertTrue(pref.getBoolean("k3", false));
        assertEquals(testSet, pref.getStringSet("set", null));
        pref.close();

        // open with new pw, should be accessible
        pref = create(name, clonePassword(newPassword))
                .keyStretchingFunction(new FastKeyStretcher()).build();
        assertEquals("string1", pref.getString("k1", null));
        assertEquals(2, pref.getInt("k2", 0));
        assertTrue(pref.getBoolean("k3", false));
        assertEquals(testSet, pref.getStringSet("set", null));
        pref.close();

        // open with old pw, should throw exception, since cannot decrypt
        pref = create(name, clonePassword(currentPassword))
                .keyStretchingFunction(new FastKeyStretcher()).build();
        try {
            pref.getString("k1", null);
            fail("should throw exception, since cannot decrypt");
        } catch (SecureSharedPreferenceCryptoException ignored) {
        }
    }
    
    private char[] clonePassword(char[] password) {
        return password == null ? null : password.clone();
    }

    @Test
    public void testChangePasswordAndKeyStretchingFunction() {
        Set<String> testSet = new HashSet<>();
        testSet.add("t1");
        testSet.add("t2");
        testSet.add("t3");

        // open new shared pref and add some data
        ArmadilloSharedPreferences pref = create("testChangePassword", "pw1".toCharArray())
                .keyStretchingFunction(new BrokenBcryptKeyStretcher(8)).build();
        pref.edit().putString("k1", "string1").putInt("k2", 2).putStringSet("set", testSet)
                .putBoolean("k3", true).commit();
        pref.close();

        // open again and check if can be used
        pref = create("testChangePassword", "pw1".toCharArray())
                .keyStretchingFunction(new BrokenBcryptKeyStretcher(8)).build();
        assertEquals("string1", pref.getString("k1", null));
        assertEquals(2, pref.getInt("k2", 0));
        assertTrue(pref.getBoolean("k3", false));
        assertEquals(testSet, pref.getStringSet("set", null));
        pref.close();

        // open with old pw and old ksFn; change to new one, all the values should be accessible
        pref = create("testChangePassword", "pw1".toCharArray())
                .keyStretchingFunction(new BrokenBcryptKeyStretcher(8)).build();
        pref.changePassword("pw2".toCharArray(), new ArmadilloBcryptKeyStretcher(8));
        assertEquals("string1", pref.getString("k1", null));
        assertEquals(2, pref.getInt("k2", 0));
        assertTrue(pref.getBoolean("k3", false));
        assertEquals(testSet, pref.getStringSet("set", null));
        pref.close();

        // open with new pw and new ksFn, should be accessible
        pref = create("testChangePassword", "pw2".toCharArray())
            .keyStretchingFunction(new ArmadilloBcryptKeyStretcher(8)).build();
        assertEquals("string1", pref.getString("k1", null));
        assertEquals(2, pref.getInt("k2", 0));
        assertTrue(pref.getBoolean("k3", false));
        assertEquals(testSet, pref.getStringSet("set", null));
        pref.close();

        // open with new pw and old ksFn, should throw exception, since cannot decrypt
        pref = create("testChangePassword", "pw2".toCharArray())
                .keyStretchingFunction(new BrokenBcryptKeyStretcher(8)).build();
        try {
            pref.getString("k1", null);
            fail("should throw exception, since cannot decrypt");
        } catch (SecureSharedPreferenceCryptoException ignored) {
        }

        // open with old pw and old ksFn, should throw exception, since cannot decrypt
        pref = create("testChangePassword", "pw1".toCharArray())
                .keyStretchingFunction(new BrokenBcryptKeyStretcher(8)).build();
        try {
            pref.getString("k1", null);
            fail("should throw exception, since cannot decrypt");
        } catch (SecureSharedPreferenceCryptoException ignored) {
        }
    }

    @Test
    public void testInvalidPasswordShouldNotBeAccessible() {
        // open new shared pref and add some data
        ArmadilloSharedPreferences pref = create("testInvalidPassword", "pw1".toCharArray())
                .keyStretchingFunction(new FastKeyStretcher()).build();
        pref.edit().putString("k1", "string1").putInt("k2", 2).putBoolean("k3", true).commit();
        pref.close();

        // open again and check if can be used
        pref = create("testInvalidPassword", "pw1".toCharArray())
                .keyStretchingFunction(new FastKeyStretcher()).build();
        assertEquals("string1", pref.getString("k1", null));
        assertEquals(2, pref.getInt("k2", 0));
        assertTrue(pref.getBoolean("k3", false));
        pref.close();

        // open with invalid pw, should throw exception, since cannot decrypt
        pref = create("testInvalidPassword", "pw2".toCharArray())
                .keyStretchingFunction(new FastKeyStretcher()).build();
        try {
            pref.getString("k1", null);
            fail("should throw exception, since cannot decrypt");
        } catch (SecureSharedPreferenceCryptoException ignored) {
        }
        try {
            pref.getInt("k2", 0);
            fail("should throw exception, since cannot decrypt");
        } catch (SecureSharedPreferenceCryptoException ignored) {
        }
        try {
            pref.getBoolean("k3", false);
            fail("should throw exception, since cannot decrypt");
        } catch (SecureSharedPreferenceCryptoException ignored) {
        }
    }

    @Test
    public void testUpgradeToNewerProtocolVersion() {
        assumeFalse("test not supported on kitkat devices", isKitKatOrBelow());

        // open new preference with old encryption config
        ArmadilloSharedPreferences pref = create("testUpgradeToNewerProtocolVersion", null)
                .symmetricEncryption(new AesCbcEncryption())
                .cryptoProtocolVersion(-19).build();

        // add some data
        pref.edit().putString("k1", "string1").putInt("k2", 2).putBoolean("k3", true).commit();
        pref.close();

        // open again with encryption config
        pref = create("testUpgradeToNewerProtocolVersion", null)
                .symmetricEncryption(new AesCbcEncryption())
                .cryptoProtocolVersion(-19).build();

        // check data
        assertEquals("string1", pref.getString("k1", null));
        assertEquals(2, pref.getInt("k2", 0));
        assertTrue(pref.getBoolean("k3", false));
        pref.close();

        // open with new config and add old config as support config
        pref = create("testUpgradeToNewerProtocolVersion", null)
                .symmetricEncryption(new AesGcmEncryption())
                .cryptoProtocolVersion(0)
                .addAdditionalDecryptionProtocolConfig(EncryptionProtocolConfig
                        .newDefaultConfig()
                        .authenticatedEncryption(new AesCbcEncryption())
                        .protocolVersion(-19)
                        .build())
                .build();

        // check data
        assertEquals("string1", pref.getString("k1", null));
        assertEquals(2, pref.getInt("k2", 0));
        assertTrue(pref.getBoolean("k3", false));

        // add some data
        pref.edit().putString("j1", "string2").putInt("j2", 3).putBoolean("j3", false).commit();

        pref.close();

        // open again with new config and add old config as support config
        pref = create("testUpgradeToNewerProtocolVersion", null)
                .symmetricEncryption(new AesGcmEncryption())
                .cryptoProtocolVersion(0)
                .addAdditionalDecryptionProtocolConfig(EncryptionProtocolConfig
                        .newDefaultConfig()
                        .authenticatedEncryption(new AesCbcEncryption())
                        .protocolVersion(-19)
                        .build())
                .build();

        // check data
        assertEquals("string1", pref.getString("k1", null));
        assertEquals(2, pref.getInt("k2", 0));
        assertTrue(pref.getBoolean("k3", false));
        assertEquals("string2", pref.getString("j1", null));
        assertEquals(3, pref.getInt("j2", 0));
        assertFalse(pref.getBoolean("j3", true));

        pref.close();

        // open again with new config and add old config as support config
        pref = create("testUpgradeToNewerProtocolVersion", null)
                .symmetricEncryption(new AesGcmEncryption())
                .cryptoProtocolVersion(0)
                .addAdditionalDecryptionProtocolConfig(EncryptionProtocolConfig
                        .newDefaultConfig()
                        .authenticatedEncryption(new AesCbcEncryption())
                        .protocolVersion(-19)
                        .build())
                .clearAdditionalDecryptionProtocolConfigs()
                .build();

        try {
            pref.getString("k1", null);
            fail("should throw exception, since cannot decrypt");
        } catch (SecureSharedPreferenceCryptoException ignored) {
        }
    }
}
