package at.favre.lib.armadillo;

import android.support.annotation.NonNull;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Collections;

import at.favre.lib.bytes.Bytes;

import static org.junit.Assert.assertArrayEquals;

public class DefaultEncryptionProtocolTest {

    @Test
    public void testEncryptDecrypt() throws Exception {
        testEncryptDecrypt(Bytes.random(20).encodeHex(), Bytes.random(1).array(), null);
        testEncryptDecrypt(Bytes.random(20).encodeHex(), Bytes.random(16).array(), null);
        testEncryptDecrypt(Bytes.random(20).encodeHex(), Bytes.random(16).array(), "1234".toCharArray());
        testEncryptDecrypt(Bytes.random(20).encodeHex(), Bytes.random(354).array(), "乨ØǲǲɻaД\u058DAא\u08A1A2$ᶀṻὉ\u202A₸ꜽ!ö\uD83E\uDD2Fײַ".toCharArray());
    }

    private EncryptionProtocol testEncryptDecrypt(String contentKey, byte[] content, char[] pw) throws EncryptionProtocolException {
        EncryptionProtocol protocol = createDefaultProtocol(new TestEncryptionFingerprint());
        byte[] encrypted = protocol.encrypt(contentKey, pw, content);

        // decrypt twice so state does not matter
        assertArrayEquals(content, protocol.decrypt(contentKey, pw, encrypted));
        assertArrayEquals(content, protocol.decrypt(contentKey, pw, encrypted));
        return protocol;
    }

    @Test
    public void testAgainstHardcodedValuesToSpotMigrationIssues() throws Exception {
        testDecrypt("969f3276e85b74af6154ce6ddf912c334cf311b3",
                "122919b282023568695c04a863f32e3f",
                null,
                "0000000010ddd75ec912994a21bfe6e85e7264f77e0000002d7e9beac3c605c0fbecf5c4b3e119b35b40469683e0ca82285d51799926788630cdfe5d7ca27e77bddd4d8260b1");

        testDecrypt("969f3276e85b74af6154ce6ddf912c334cf311b3",
                "122919b282023568695c04a863f32e3f",
                "1234",
                "000000001034ccac29ba0ad1ed80475d991dce29ee0000002d7e1c39db5d17df6f84ebe6805115125e702b2ae6fe0ba49a16e8281fb08e0733e53310ed677814965491ffeb9c");

        testDecrypt("969f3276e85b74af6154ce6ddf912c334cf311b3",
                "122919b282023568695c04a863f32e3f",
                "1234",
                "0000000010e96ba92b343976ee8858f1d6143a42cc0000002d7e9d7318b1a420dd090ac5bd7d65ddc9e3e3c8f87547719b5ac20c6f03501235ad03909b4fdcd7864aae018e4a");

        testDecrypt("df60a9c11db3fd443cd89def85d8ff046683ae27",
                "b94325505418d8cf56fdca8c3e096a5f813a9ad84937ed99e28bce0a3f259bee83834e0bee24705720da13",
                "乨ØǲǲɻaД\u058DAא\u08A1A2",
                "0000000010b6b7daf84c988d3dc5034a52cddd91c50000004833aacb15329f192ff4542c5d010fcd1fc747306757d69b2869641c827115a4cd274b55b4f6c08277ef8cd565abc515a9bc03cf6c2b960588079ced91106dad418af12a16bd7069e8");
    }

    private void testDecrypt(String contentKey, String contentHex, String pw, String refContent) throws Exception {
        byte[] fingerprint = Bytes.parseHex("f5ce0a3105f75006008608edf417b40d").array();
        byte[] preferencesSalt = Bytes.parseHex("9752f5ea8c8a35446d22d6a59d1d1b0544c5978d").array();
        EncryptionProtocol protocol = createDefaultProtocolFactory(new TestEncryptionFingerprint(fingerprint)).create(preferencesSalt);
        //byte[] enc = protocol.encrypt(contentKey,null, Bytes.parseHex(contentHex).array());
        assertArrayEquals(Bytes.parseHex(contentHex).array(), protocol.decrypt(contentKey, pw != null ? pw.toCharArray() : null, Bytes.parseHex(refContent).array()));
    }

    @Test
    public void obfuscatePassword() {
        testObfuscatePw("123456abcdefABCDEF_:;$%&/()=?\"}][{");
        testObfuscatePw("5187h_asd€éÀä'#\uD83E\uDD2F#_");
        testObfuscatePw("µ€ßüöäáé´Ààó");
        testObfuscatePw("乨ØǲǲɻД\u058Dא\u08A1ᶀṻὉ\u202A₸ꜽײַ");
        testObfuscatePw("乨ØǲǲɻaД\u058DAא\u08A1A2$ᶀṻὉ\u202A₸ꜽ!ö\uD83E\uDD2Fײַ");
    }

    private void testObfuscatePw(String pwString) {
        EncryptionProtocol protocol = createDefaultProtocol(new TestEncryptionFingerprint());

        char[] pw = pwString.toCharArray();
        ByteArrayRuntimeObfuscator o = protocol.obfuscatePassword(pw);
        char[] pw2 = protocol.deobfuscatePassword(o);

        assertArrayEquals(pw, pw2);
    }

    @Test
    public void testWipeCache() throws Exception {
        EncryptionProtocol protocol = createDefaultProtocol(new TestEncryptionFingerprint());
        String contentKey = Bytes.random(20).encodeHex();
        byte[] content = Bytes.random(354).array();
        char[] pw = "乨ØǲǲɻaД\u058DAא\u08A1A2$ᶀṻὉ\u202A₸ꜽ!ö\uD83E\uDD2Fײַ".toCharArray();
        byte[] encrypted = protocol.encrypt(contentKey, pw, content);

        protocol.decrypt(contentKey, pw, encrypted);
        protocol.decrypt(contentKey, pw, encrypted);
        protocol.decrypt(contentKey, pw, encrypted);

        protocol.wipeDerivedPasswordCache();

        protocol.decrypt(contentKey, pw, encrypted);
    }

    @NonNull
    private EncryptionProtocol createDefaultProtocol(EncryptionFingerprint fingerprint) {
        return createDefaultProtocolFactory(fingerprint).create(Bytes.random(16).array());
    }

    private EncryptionProtocol.Factory createDefaultProtocolFactory(EncryptionFingerprint fingerprint) {
        return new DefaultEncryptionProtocol
                .Factory(EncryptionProtocolConfig.newBuilder()
                .protocolVersion(0)
                .keyStrength(AuthenticatedEncryption.STRENGTH_HIGH)
                .authenticatedEncryption(new AesGcmEncryption())
                .compressor(new DisabledCompressor())
                .dataObfuscatorFactory(new HkdfXorObfuscator.Factory())
                .keyStretchingFunction(new ArmadilloBcryptKeyStretcher(4))
                .build(),
                fingerprint, new HkdfMessageDigest(new byte[16], 20), new SecureRandom(),
                false, Collections.emptyList());
    }
}
