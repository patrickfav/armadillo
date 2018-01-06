package at.favre.lib.armadillo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * A compressor using Gzip algorithm provided by the JDK
 *
 * @author Patrick Favre-Bulle
 * @since 06.01.2018
 */
public final class GzipCompressor implements Compressor {

    public GzipCompressor() {
    }

    @Override
    public byte[] compress(byte[] uncompressed) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        GZIPInputStream gzipInputStream = null;
        byte[] returnBuffer;
        try {
            int len;
            byte[] buffer = new byte[2048];
            gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(uncompressed));

            while ((len = gzipInputStream.read(buffer)) > 0) {
                bos.write(buffer, 0, len);
            }

            gzipInputStream.close();
            returnBuffer = bos.toByteArray();
            bos.close();
            return returnBuffer;
        } catch (Exception e) {
            throw new IllegalStateException("could not decompress gzip", e);
        }
    }

    @Override
    public byte[] decompress(byte[] compressed) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(compressed.length);
        GZIPOutputStream gzipOutputStream = null;
        byte[] returnBuffer;
        try {
            gzipOutputStream = new GZIPOutputStream(bos);
            gzipOutputStream.write(compressed);
            gzipOutputStream.close();
            returnBuffer = bos.toByteArray();
            bos.close();
            return returnBuffer;
        } catch (Exception e) {
            throw new IllegalStateException("could not compress gzip", e);
        }
    }
}
