package at.favre.lib.armadillo;

import org.junit.Before;
import org.junit.Test;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformers;

import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;

public class GzipCompressorTest {
    private Compressor compressor;

    @Before
    public void setup() {
        compressor = new GzipCompressor();
    }

    @Test
    public void compress() throws Exception {
        byte[] original = Bytes.random(128).append(Bytes.allocate(1024)).transform(BytesTransformers.shuffle()).array();
        byte[] compressed = compressor.compress(original);
        assertTrue(compressed.length < original.length);
    }

    @Test
    public void decompress() throws Exception {
        testCompressDecompress(1);
        testCompressDecompress(12);
        testCompressDecompress(128);
        testCompressDecompress(512);
        testCompressDecompress(2048);
        testCompressDecompress(8096);
    }

    private void testCompressDecompress(int messageLength) {
        byte[] original = Bytes.random(16).append(Bytes.allocate(messageLength)).transform(BytesTransformers.shuffle()).array();
        byte[] compressed = compressor.compress(original);
        byte[] uncompressed = compressor.decompress(compressed);
        assertArrayEquals(original, uncompressed);
    }
}
