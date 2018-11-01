package at.favre.lib.armadillo;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;

public class DefaultEncryptionProtocolTest {

    @Before
    public void setUp() {
    }

    @Test
    public void obfuscatePassword() {
        EncryptionProtocol protocol = new DefaultEncryptionProtocol
            .Factory(0, new TestEncryptionFingerprint(), new HkdfMessageDigest(new byte[16], 20), new AesGcmEncryption(),
            AuthenticatedEncryption.STRENGTH_HIGH, new FastKeyStretcher(), new HkdfXorObfuscator.Factory(),
            new SecureRandom(), null).create(new byte[16]);

        char[] pw = "5187h_asd€éÀä'#\uD83E\uDD2F#_".toCharArray();
        ByteArrayRuntimeObfuscator o = protocol.obfuscatePassword(pw);
        char[] pw2 = protocol.deobfuscatePassword(o);

        assertArrayEquals(pw, pw2);
    }
}
