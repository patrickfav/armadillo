package at.favre.lib.armadillo;

import at.favre.lib.bytes.Bytes;

public class SecureSharedPreferenceUnitTest extends ASecureSharedPreferencesTest {
    @Override
    protected Armadillo.Builder create(String name, char[] pw) {
        return Armadillo.create(new MockSharedPref())
                .encryptionFingerprint(Bytes.random(16).array())
                .password(pw);
    }
}
