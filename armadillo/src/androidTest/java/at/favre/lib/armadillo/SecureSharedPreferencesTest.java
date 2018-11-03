package at.favre.lib.armadillo;

import android.content.Context;
import android.content.SharedPreferences;
import android.provider.Settings;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;
import at.favre.lib.bytes.Bytes;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class SecureSharedPreferencesTest extends ASecureSharedPreferencesTest {
    protected Armadillo.Builder create(String name, char[] pw) {
        return Armadillo.create(InstrumentationRegistry.getTargetContext(), name)
            .encryptionFingerprint(InstrumentationRegistry.getTargetContext())
            .password(pw);
    }

    @Test
    public void quickStartTest() {
        Context context = InstrumentationRegistry.getTargetContext();
        SharedPreferences preferences = Armadillo.create(context, "myPrefs")
            .encryptionFingerprint(context)
            .build();

        preferences.edit().putString("key1", "string").apply();
        String s = preferences.getString("key1", null);
    }

    @Test
    public void testWithDifferentKeyStrength() {
        preferenceSmokeTest(create("fingerprint", null)
            .encryptionKeyStrength(AuthenticatedEncryption.STRENGTH_VERY_HIGH).build());
    }

    @Test
    public void advancedTest() {
        Context context = InstrumentationRegistry.getTargetContext();
        String userId = "1234";
        SharedPreferences preferences = Armadillo.create(context, "myCustomPreferences")
            .password("mySuperSecretPassword".toCharArray()) //use user based password
            .securityProvider(Security.getProvider("BC")) //use bouncy-castle security provider
            .keyStretchingFunction(new PBKDF2KeyStretcher()) //use PBKDF2 as user password kdf
            .contentKeyDigest(Bytes.from(getAndroidId(context)).array()) //use custom content key digest salt
            .secureRandom(new SecureRandom()) //provide your own secure random for salt/iv generation
            .encryptionFingerprint(context, userId.getBytes(StandardCharsets.UTF_8)) //add the user id to fingerprint
            .supportVerifyPassword(true) //enables optional password validation support `.isValidPassword()`
            .build();

        preferences.edit().putString("key1", "string").apply();
        String s = preferences.getString("key1", null);
    }

    private String getAndroidId(Context context) {
        return Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
    }
}
