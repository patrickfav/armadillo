package at.favre.lib.armadillo;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static at.favre.lib.armadillo.Armadillo.log;

/**
 * A compressor using Gzip algorithm provided by the JDK
 *
 * @author Patrick Favre-Bulle
 * @since 06.01.2018
 */
public final class GzipCompressor implements Compressor {
    private static final String TAG = GzipCompressor.class.getSimpleName();

    public GzipCompressor() {
    }

    @Override
    public byte[] decompress(byte[] compressed) {
        byte[] returnBuffer;
        byte[] buffer = new byte[2048];
        int len;
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); GZIPInputStream gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressed))) {

            while ((len = gzipInputStream.read(buffer)) > 0) {
                bos.write(buffer, 0, len);
            }

            gzipInputStream.close();
            returnBuffer = bos.toByteArray();
            bos.close();
            log(Log.VERBOSE, TAG, "compression saved %d byte", compressed.length - returnBuffer.length);
            return returnBuffer;
        } catch (Exception e) {
            throw new IllegalStateException("could not decompress gzip", e);
        }
    }

    @Override
    public byte[] compress(byte[] uncompressed) {
        byte[] returnBuffer;
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream(uncompressed.length); GZIPOutputStream gzipOutputStream = new GZIPOutputStream(bos)) {
            gzipOutputStream.write(uncompressed);
            gzipOutputStream.close();
            returnBuffer = bos.toByteArray();
            bos.close();
            return returnBuffer;
        } catch (Exception e) {
            throw new IllegalStateException("could not compress gzip", e);
        }
    }
}
