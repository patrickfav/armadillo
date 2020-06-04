package at.favre.lib.armadillo;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import androidx.annotation.Nullable;

import java.io.ByteArrayOutputStream;

import at.favre.lib.bytes.Bytes;

import static at.favre.lib.armadillo.Armadillo.log;

/**
 * Factory for creating {@link EncryptionFingerprintFactory} in Android
 *
 * @author Patrick Favre-Bulle
 * @since 19.12.2017
 */

public final class EncryptionFingerprintFactory {
    private static final String TAG = EncryptionFingerprintFactory.class.getSimpleName();

    private EncryptionFingerprintFactory() {
    }

    /**
     * Creates a new {@link EncryptionFingerprint} including the following data:
     * <ul>
     * <li>Fingerprint of the APK signature</li>
     * <li>Android ID: a 8 byte random value on SDK 26 and higher,
     * unique to each combination of app-signing key, user, and device - on SDK 25 and lower only unique
     * to user and device</li>
     * <li>Application package name, Brand, model and name of the device</li>
     * <li>32 byte hardcoded static random value</li>
     * </ul>
     * <p>
     * It is recommended to provide additional data unique to your domain (e.g. userId, api version, etc).
     * <p>
     * <em>Note:</em> If the fingerprint changes the data cannot be decrypted anymore.
     *
     * @param context        used to gather data from the Android framework
     * @param additionalData additional data provided by the caller
     * @return fingerprint
     */
    public static EncryptionFingerprint create(Context context, @Nullable String additionalData) {
        return new EncryptionFingerprint.Default(Bytes.from(getApkSignatureHash(context),
                Bytes.from(getAndroidId(context)).array(),
                Bytes.from(getApplicationPackage(context)).array(),
                Bytes.from(getBuildDetails()).array(),
                BuildConfig.STATIC_RANDOM,
                additionalData != null ? Bytes.from(additionalData).array() : Bytes.empty().array()).array());
    }

    /**
     * Get some OS build data
     *
     * @return string including the info
     */
    private static String getBuildDetails() {
        return Build.DEVICE + Build.MODEL + Build.MANUFACTURER;
    }

    /**
     * Gets the application package name e.g. "at.favre.app"
     *
     * @param context from Android
     * @return package
     */
    @SuppressLint("HardwareIds")
    private static String getApplicationPackage(Context context) {
        return String.valueOf(context.getApplicationContext().getPackageName());
    }

    /**
     * Gets the 64-bit number (expressed as a hexadecimal string) byte random value; on SDK 26 and higher,
     * unique to each combination of app-signing key, user, and device - on SDK 25 and lower only unique
     * to user and device
     *
     * @param context from Android
     * @return android id or fallback if
     */
    @SuppressLint("HardwareIds")
    private static String getAndroidId(Context context) {
        String androidId = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        if (androidId == null) { // fallback on devices that incorrectly return null
            log(Log.WARN, TAG, "This devices returned null as ANDROID_ID, using fallback. This is not expected and may be a device bug. If this behaviour is non-deterministic, it may disrupt the possibility of decrypting the content.");
            return BuildConfig.ANDROID_ID_FALLBACK;
        }
        return androidId;
    }

    /**
     * Gets the SHA-256 hashed fingerprint of the APK signature
     *
     * @param context from Android
     * @return 32 bytes sha256 hash
     */
    private static byte[] getApkSignatureHash(Context context) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            @SuppressLint("PackageManagerGetSignatures")
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            for (Signature signature : packageInfo.signatures) {
                bos.write(signature.toByteArray());
            }
            return Bytes.wrap(bos.toByteArray()).hashSha256().array();
        } catch (Exception e) {
            throw new IllegalStateException("could not get apk signature hash", e);
        }
    }
}
