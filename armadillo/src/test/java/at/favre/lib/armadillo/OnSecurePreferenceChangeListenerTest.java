package at.favre.lib.armadillo;

import android.content.SharedPreferences;
import android.support.annotation.NonNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import at.favre.lib.bytes.Bytes;

import static junit.framework.TestCase.assertEquals;

/**
 * Tests for the {@link OnSecurePreferenceChangeListener}
 */
public class OnSecurePreferenceChangeListenerTest {

    private ArmadilloSharedPreferences armadilloSharedPreferences;
    private TestSecurePreferenceChange testSecurePreferenceChange = new TestSecurePreferenceChange("target-key");
    private final MockSharedPref mockSharedPref = new MockSharedPref();

    @Before
    public void onSetup() {
        armadilloSharedPreferences = Armadillo.create(mockSharedPref).encryptionFingerprint(Bytes.parseHex("6894964e2be3b5aaed5ca8c2724f4915").array())
                                              .password("1234".toCharArray())
                                              .build();

        armadilloSharedPreferences.registerOnSecurePreferenceChangeListener(testSecurePreferenceChange);
    }

    @After
    public void onCleanup() {
        armadilloSharedPreferences.unregisterOnSecurePreferenceChangeListener(testSecurePreferenceChange);
    }

    @Test
    public void testUpdatedKeyNotifiesProperly() {
        armadilloSharedPreferences.edit().putString("target-key", "a new hope").apply();
        assertEquals("a new hope", testSecurePreferenceChange.getNewValue());
    }

    @Test
    public void testUpdateAnotherCanBeIgnored() {
        armadilloSharedPreferences.edit().putString("different-key", "a new hope").apply();
        assertEquals(0, testSecurePreferenceChange.getNumHits());
    }

    @Test
    public void testImplementationRegistersListenerWithPlatformPreferences() {
        assertEquals(1, mockSharedPref.getNumListeners());
    }

    @Test
    public void testUnregisterAlsoUnregistersPlatform() {
        armadilloSharedPreferences.unregisterOnSecurePreferenceChangeListener(testSecurePreferenceChange);
        assertEquals(0, mockSharedPref.getNumListeners());
    }

    private static final class TestSecurePreferenceChange implements OnSecurePreferenceChangeListener {
        private final String expectedKey;
        private String newValue;
        private int numHits = 0;

        private TestSecurePreferenceChange(String expectedKey) {
            this.expectedKey = expectedKey;
        }

        @Override
        public void onSecurePreferenceChanged(@NonNull SharedPreferences sharedPreferences, @NonNull DerivedKeyComparison comparison) {
            if (comparison.isDerivedKeyEqualTo(expectedKey)) {
                newValue = sharedPreferences.getString(expectedKey, null);
                numHits++;
            }
        }

        String getNewValue() {
            return newValue;
        }

        int getNumHits() {
            return numHits;
        }
    }
}
