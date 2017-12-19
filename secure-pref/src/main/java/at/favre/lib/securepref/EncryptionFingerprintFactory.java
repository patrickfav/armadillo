package at.favre.lib.securepref;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.provider.Settings;
import android.support.annotation.Nullable;

import java.io.ByteArrayOutputStream;

import at.favre.lib.bytes.Bytes;

/**
 * @author RISE GmbH (patrick.favre@rise-world.com)
 * @since 19.12.2017
 */

public class EncryptionFingerprintFactory {

    public static EncryptionFingerprint create(Context context, @Nullable String additionalData) {
        return () -> Bytes.wrap(getApkSignatureHash(context))
                .append(Bytes.from(getAndroidId(context)))
                .append(BuildConfig.STATIC_RANDOM)
                .append(additionalData != null ? Bytes.from(additionalData) : Bytes.from("")).array();
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
