package at.favre.lib.securepref;

import android.content.SharedPreferences;

import at.favre.lib.bytes.Bytes;

public class SecureSharedPreferenceUnitTest extends ASecureSharedPreferencesTest {
    @Override
    protected SharedPreferences create(String name, char[] pw) {
        return Armadillo.create(new MockSharedPref())
                .encryptionFingerprint(Bytes.random(16).array())
                .password(pw)
                .build();
    }
}
