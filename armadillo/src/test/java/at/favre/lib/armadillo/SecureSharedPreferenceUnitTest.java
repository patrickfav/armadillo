package at.favre.lib.armadillo;

import android.content.SharedPreferences;

import java.util.HashMap;
import java.util.Map;

public class SecureSharedPreferenceUnitTest extends ASecureSharedPreferencesTest {
    private Map<String, MockSharedPref> prefMap = new HashMap<>();

    @Override
    protected Armadillo.Builder create(String name, char[] pw) {
        return Armadillo.create(getOrCreate(name))
                .encryptionFingerprint(new byte[16])
                .password(pw);
    }

    private SharedPreferences getOrCreate(String name) {
        if (!prefMap.containsKey(name)) {
            prefMap.put(name, new MockSharedPref());
        }
        return prefMap.get(name);
    }
}
