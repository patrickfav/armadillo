package at.favre.lib.armadillo;

import at.favre.lib.bytes.Bytes;

public class TestEncryptionFingerprint implements EncryptionFingerprint {
    private final byte[] fp;

    public TestEncryptionFingerprint() {
        this(Bytes.random(16).array());
    }

    public TestEncryptionFingerprint(byte[] fp) {
        this.fp = fp;
    }

    @Override
    public byte[] getBytes() {
        return Bytes.wrap(fp).copy().array();
    }

    @Override
    public void wipe() {
        Bytes.wrap(fp).mutable().secureWipe();
    }
}
