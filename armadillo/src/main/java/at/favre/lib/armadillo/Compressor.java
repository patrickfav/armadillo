package at.favre.lib.armadillo;

/**
 * Compresses the given byte array with a lossless compression technique (like gzip)
 *
 * @author Patrick Favre-Bulle
 * @since 06.01.2018
 */
interface Compressor {
    /**
     * Compress given uncompressed byte array
     *
     * @param uncompressed to compress
     * @return a new byte array with the compressed data
     */
    byte[] compress(byte[] uncompressed);

    /**
     * Decompress a byte array that was compressed with {@link #compress(byte[])}
     *
     * @param compressed to decompress
     * @return a new byte array with the decompressed data
     */
    byte[] decompress(byte[] compressed);

}
