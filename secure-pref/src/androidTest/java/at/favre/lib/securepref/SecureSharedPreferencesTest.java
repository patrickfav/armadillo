package at.favre.lib.securepref;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.runner.RunWith;

import java.security.SecureRandom;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class SecureSharedPreferencesTest extends ASecureSharedPreferencesTest {
    protected SecureSharedPreferences create(String name, char[] pw) {
        Context appContext = InstrumentationRegistry.getTargetContext();
        SecureRandom secureRandom = new SecureRandom();
        EncryptionFingerprint fingerprint = EncryptionFingerprintFactory.create(appContext, null);
        return new SecureSharedPreferences(
                appContext,
                name,
                new DefaultEncryptionProtocol.Factory(
                        fingerprint, new HkdfKeyDigest(BuildConfig.PREF_SALT, 20),
                        new AesGcmEncryption(), SymmetricEncryption.STRENGTH_HIGH,
                        new PBKDF2KeyStretcher(), new HkdfXorObfuscator.Factory(), secureRandom), pw);
    }
}
