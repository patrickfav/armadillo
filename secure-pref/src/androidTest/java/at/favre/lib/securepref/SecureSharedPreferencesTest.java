package at.favre.lib.securepref;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.SecureRandom;

import at.favre.lib.bytes.Bytes;

import static org.junit.Assert.assertEquals;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class SecureSharedPreferencesTest {
    @Test
    public void simpleStringGet() throws Exception {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getTargetContext();

        SecureRandom secureRandom = new SecureRandom();
        EncryptionFingerprint fingerprint = EncryptionFingerprintFactory.create(appContext, null);

        SharedPreferences preferences = new SecureSharedPreferences(
                appContext,
                "test",
                new DefaultEncryptionProtocol(
                        new AesGcmEncryption(secureRandom), pw -> Bytes.from(String.valueOf(pw)).array(),
                        SymmetricEncryption.STRENGTH_HIGH,
                        fingerprint, BuildConfig.PREF_SALT));

        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 100; j++) {
                String content = "testäI/_²~"+Bytes.random(64+j).encodeHex();
                preferences.edit().putString("k"+j, content).apply();
                assertEquals(content, preferences.getString("k"+j, null));
            }
        }
    }
}
