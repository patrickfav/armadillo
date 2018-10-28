package at.favre.lib.armadillo;

import android.content.SharedPreferences;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static junit.framework.Assert.assertTrue;

public class SecureSharedPreferenceUnitTest extends ASecureSharedPreferencesTest {
    private Map<String, MockSharedPref> prefMap = new HashMap<>();

    @Override
    protected Armadillo.Builder create(String name, char[] pw) {
        return Armadillo.create(getOrCreate(name))
                .encryptionFingerprint(new byte[16])
                .password(pw);
    }

    @Override
    protected boolean isKitKatOrBelow() {
        return false;
    }

    private SharedPreferences getOrCreate(String name) {
        if (!prefMap.containsKey(name)) {
            prefMap.put(name, new MockSharedPref());
        }
        return prefMap.get(name);
    }

    @Test
    public void testChangeListener() {
        AtomicBoolean b = new AtomicBoolean(false);
        SharedPreferences.OnSharedPreferenceChangeListener listener = (sharedPreferences, s) -> b.set(true);
        preferences.registerOnSharedPreferenceChangeListener(listener);
        preferences.edit().putString("s", "test").commit();
        assertTrue(b.get());
        preferences.unregisterOnSharedPreferenceChangeListener(listener);
    }
}
