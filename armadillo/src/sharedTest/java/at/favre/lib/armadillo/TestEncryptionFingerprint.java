package at.favre.lib.armadillo;

import at.favre.lib.bytes.Bytes;

public class TestEncryptionFingerprint implements EncryptionFingerprint {
    private byte[] fp = Bytes.random(16).array();

    @Override
    public byte[] getBytes() {
        return fp;
    }

    @Override
    public void wipe() {
        Bytes.wrap(fp).mutable().secureWipe();
    }
}
