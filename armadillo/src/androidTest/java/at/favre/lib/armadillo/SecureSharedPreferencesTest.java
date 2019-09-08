package at.favre.lib.armadillo;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.support.test.InstrumentationRegistry;
import android.support.test.annotation.UiThreadTest;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;

import at.favre.lib.bytes.Bytes;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

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
                .enableKitKatSupport(isKitKatOrBelow())
                .password(pw);
    }

    @Override
    protected boolean isKitKatOrBelow() {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP;
    }

    @Test
    public void quickStartTest() {
        Context context = InstrumentationRegistry.getTargetContext();
        SharedPreferences preferences = Armadillo.create(context, "myPrefs")
                .encryptionFingerprint(context)
                .enableKitKatSupport(isKitKatOrBelow()).build();

        preferences.edit().putString("key1", "string").apply();
        String s = preferences.getString("key1", null);

        assertEquals("string", s);
    }

    @Test
    public void testWithDifferentKeyStrength() {
        preferenceSmokeTest(create("fingerprint", null)
                .encryptionKeyStrength(AuthenticatedEncryption.STRENGTH_VERY_HIGH).build());
    }

    @Test
    @UiThreadTest
    public void testSecurePreferenceChangeNotification() {
        ArmadilloSharedPreferences armadilloSharedPreferences = create("fingerprint", null).build();
        AtomicBoolean matched = new AtomicBoolean(false);
        armadilloSharedPreferences.registerOnSecurePreferenceChangeListener(((sharedPreferences, comparison) -> {
            if (comparison.isDerivedKeyEqualTo("key-of-interest")) {
                matched.set(true);
            }
        }));

        armadilloSharedPreferences.edit().putInt("key-of-interest", 3).commit();

        assertTrue(matched.get());
    }

    @Test
    @UiThreadTest
    public void testSecurePreferenceNotMatching() {
        ArmadilloSharedPreferences armadilloSharedPreferences = create("fingerprint", null).build();
        AtomicBoolean matched = new AtomicBoolean(false);
        armadilloSharedPreferences.registerOnSecurePreferenceChangeListener(((sharedPreferences, comparison) -> {
            if (comparison.isDerivedKeyEqualTo("key-of-interest")) {
                matched.set(true);
            }
        }));

        armadilloSharedPreferences.edit().putInt("another-key", 3).commit();

        assertFalse(matched.get());
    }

    @Test
    public void advancedTest() {
        Context context = InstrumentationRegistry.getTargetContext();
        String userId = "1234";
        SharedPreferences preferences = Armadillo.create(context, "myCustomPreferences")
            .password("mySuperSecretPassword".toCharArray()) //use user based password
            .keyStretchingFunction(new PBKDF2KeyStretcher()) //use PBKDF2 as user password kdf
            .contentKeyDigest(Bytes.from(getAndroidId(context)).array()) //use custom content key digest salt
            .secureRandom(new SecureRandom()) //provide your own secure random for salt/iv generation
            .encryptionFingerprint(context, userId.getBytes(StandardCharsets.UTF_8)) //add the user id to fingerprint
            .supportVerifyPassword(true) //enables optional password validation support `.isValidPassword()`
            .enableKitKatSupport(true) //enable optional kitkat support
            .build();

        preferences.edit().putString("key1", "string").apply();
        String s = preferences.getString("key1", null);

        assertEquals("string", s);
    }

    private String getAndroidId(Context context) {
        return Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
    }
}
