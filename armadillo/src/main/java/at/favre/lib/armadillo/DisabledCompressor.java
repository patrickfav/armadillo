package at.favre.lib.armadillo;

/**
 * A compressor which does not compress anything, but just returns the same array.
 *
 * @author Patrick Favre-Bulle
 */

public class DisabledCompressor implements Compressor {
    @Override
    public byte[] compress(byte[] uncompressed) {
        return uncompressed;
    }

    @Override
    public byte[] decompress(byte[] compressed) {
        return compressed;
    }
}
