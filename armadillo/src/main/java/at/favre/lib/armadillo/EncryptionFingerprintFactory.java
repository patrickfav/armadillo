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
 * @author Patrick Favre-Bulle
 * @since 19.12.2017
 */

public final class EncryptionFingerprintFactory {

    private EncryptionFingerprintFactory() {
    }

    public static EncryptionFingerprint create(Context context, @Nullable String additionalData) {
        return new EncryptionFingerprint.Default(Bytes.wrap(getApkSignatureHash(context))
                .append(Bytes.from(getAndroidId(context)))
                .append(Bytes.from(getApplicationPackage(context)))
                .append(Bytes.from(getBuildDetails()))
                .append(BuildConfig.STATIC_RANDOM)
                .append(additionalData != null ? Bytes.from(additionalData) : Bytes.from("")).array());
    }

    private static String getBuildDetails() {
        return Build.DEVICE + Build.MODEL + Build.MANUFACTURER;
    }

    @SuppressLint("HardwareIds")
    private static String getApplicationPackage(Context context) {
        return String.valueOf(context.getApplicationContext().getPackageName());
    }

    @SuppressLint("HardwareIds")
    private static String getAndroidId(Context context) {
        return Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
    }

    private static byte[] getApkSignatureHash(Context context) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            @SuppressLint("PackageManagerGetSignatures")
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            for (Signature signature : packageInfo.signatures) {
                bos.write(signature.toByteArray());
            }
            return Bytes.wrap(bos.toByteArray()).hashSha256().array();
        } catch (Exception e) {
            throw new IllegalStateException("could not apk signature has", e);
        }
    }
}
