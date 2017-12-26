package at.favre.lib.securepref;

import java.security.SecureRandom;

import at.favre.lib.bytes.Bytes;

public class SecureSharedPreferenceUnitTest extends ASecureSharedPreferencesTest {
    @Override
    protected SecureSharedPreferences create(String name, char[] pw) {
        return new SecureSharedPreferences(new MockSharedPref(),
                new DefaultEncryptionProtocol(new AesGcmEncryption(),
                new PBKDF2KeyStretcher(),
                SymmetricEncryption.STRENGTH_HIGH, new EncryptionFingerprint.Default(Bytes.random(16).array()),
                new HkdfXorObfuscator.Factory()), pw, new SecureRandom());
    }
}
