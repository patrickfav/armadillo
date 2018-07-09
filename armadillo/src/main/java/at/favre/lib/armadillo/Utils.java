package at.favre.lib.armadillo;

import android.os.Build;

class Utils {

    private Utils() {
        // Utility class
    }

    /**
     * Checks whether the device runs Android KitKat (API level 19).
     */
    static boolean isKitKat() {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP;
    }
}
