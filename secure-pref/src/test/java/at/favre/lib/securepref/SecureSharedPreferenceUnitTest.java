package at.favre.lib.securepref;

import java.security.SecureRandom;

import at.favre.lib.bytes.Bytes;

public class SecureSharedPreferenceUnitTest extends ASecureSharedPreferencesTest {
    @Override
    protected SecureSharedPreferences create(String name, char[] pw) {
        return new SecureSharedPreferences(new MockSharedPref(),
                new DefaultEncryptionProtocol.Factory(new EncryptionFingerprint.Default(Bytes.random(16).array()),
                        new HkdfKeyDigest(BuildConfig.PREF_SALT, 20),
                        new AesGcmEncryption(), SymmetricEncryption.STRENGTH_HIGH,
                        new PBKDF2KeyStretcher(), new HkdfXorObfuscator.Factory(), new SecureRandom()), pw);
    }
}
