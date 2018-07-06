package at.favre.lib.armadillo;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.provider.Settings;
import android.support.annotation.Nullable;

import java.io.ByteArrayOutputStream;

import at.favre.lib.bytes.Bytes;

/**
 * Factory for creating {@link EncryptionFingerprintFactory} in Android
 *
 * @author Patrick Favre-Bulle
 * @since 19.12.2017
 */

public final class EncryptionFingerprintFactory {

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
        return new EncryptionFingerprint.Default(Bytes.wrap(getApkSignatureHash(context))
                .append(Bytes.from(getAndroidId(context)))
                .append(Bytes.from(getApplicationPackage(context)))
                .append(Bytes.from(getBuildDetails()))
                .append(BuildConfig.STATIC_RANDOM)
                .append(additionalData != null ? Bytes.from(additionalData) : Bytes.from("")).array());
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
     * @return package
     */
    @SuppressLint("HardwareIds")
    private static String getAndroidId(Context context) {
        return Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
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
