package at.favre.lib.armadillo;

import at.favre.lib.bytes.Bytes;

class TestEncryptionFingerprint implements EncryptionFingerprint {
    private final byte[] fp;

    TestEncryptionFingerprint() {
        this(Bytes.random(16).array());
    }

    TestEncryptionFingerprint(byte[] fp) {
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
