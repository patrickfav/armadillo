package at.favre.lib.securepref;

import android.content.SharedPreferences;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import at.favre.lib.bytes.Bytes;

import static org.junit.Assert.assertEquals;

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
            preferences = create("test-prefs", null);
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    @After
    public void tearDown() {
        preferences.edit().clear().commit();
    }

    protected abstract SharedPreferences create(String name, char[] pw);

    @Test
    public void simpleMultipleStringGet() throws Exception {
        SharedPreferences preferences = create("manytest", null);
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
        String content = "testäI/_²~";
        preferences.edit().putString("string", content).commit();
        assertEquals(content, preferences.getString("string", null));
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
        Set<String> set = new HashSet<>(7);
        for (int i = 0; i < 7; i++) {
            set.add("input" + i);
        }

        preferences.edit().putStringSet("stringSet", set).commit();
        assertEquals(set, preferences.getStringSet("stringSet", null));
    }

    @Test
    public void simpleStringGetWithPassword() throws Exception {
        SharedPreferences preferences = create("withPw", "superSecret".toCharArray());
        String content = "testäI/_²~" + Bytes.random(64).encodeHex();
        preferences.edit().putString("k", content).commit();
        assertEquals(content, preferences.getString("k", null));
    }
}
