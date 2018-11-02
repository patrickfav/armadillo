package at.favre.lib.armadillo;

import org.junit.Ignore;
import org.junit.Test;

import java.util.Map;

import at.favre.lib.bytes.Bytes;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

/**
 * A bunch of hardcoded encrypted data, to check if changes in the code breaks the decryption
 */
public class ArmadilloRegressionTest {

    @Test
    public void testDefaultSettingsArmadilloWithPw() {
        //Prepared encrypted data
        MockSharedPref mockSharedPref = new MockSharedPref();
        mockSharedPref.edit()
            .putString("39e3e4f83dda81c44f8a9063196b28b3d5091fca", "GmmiDAS3CI+HZEuQsOHe2NhVx6ErvqkZj49tm9vYm4U=") //prefSalt
            .putString("530114c1905f25976081f9294c2a6c8d0a06a847", "AAAAABB7PyZ6q9Pid5lXfPFysCMHAAAAIRBjfYxnUu2XN8bxQ8qVmXc/1zs3fAAR0emKjGt5G/RGfw==")
            .putString("40732094cb71d32527f8249d9de7724ebc339d66", "AAAAABCBfkLenMSr3zYbe02kZowpAAAAIeQthEQgC53Qc7/SUugHI7BmfmENMIfnUtmp8wspdvhvHA==")
            .putString("22d3bcfade5e40875a2fa8c7d0d547c2fcc1fb6d", "AAAAABDxOyqV0jHO8ZIEMNzqY5tfAAAAJaaFUu6vcEgYW0No5+LRFylHsKR55tqnu8YOclK4k9coarX/UHk=")
            .putString("5c0c691e32f2bfe583499c57f972c95428d994a4", "AAAAABDnA5J+HFo9Qdebui5hVf5nAAAAPiBSgkCl0nL8nB3brywfj4cVKDWknNekD5D2pwEL6Ckf1P0aW3EYTIPjDSGujTKuC+FHSDn2W+VNlmpsaiaB")
            .putString("71b30b8850406d961b3ab23d181aec46acadeb62", "AAAAABD8V91CW9gILdamchBedN4eAAAAHlGPWteha4KthrM/DbE10PUzK3oadDxHr8GRVOQ3Rw==")
            .commit();

        ArmadilloSharedPreferences a = Armadillo.create(mockSharedPref).encryptionFingerprint(Bytes.parseHex("6894964e2be3b5aaed5ca8c2724f4915").array())
            .password("1234".toCharArray()).build();

        assertTrue(a.getBoolean("aBoolean", false));
        assertEquals(5623, a.getInt("aInt", -1));
        assertEquals(8281.923452f, a.getFloat("aFloat", 0.0f));
        assertEquals(108731871230172893L, a.getLong("aLong", 0L));
        assertEquals("87adhpn2p807 1807g oasfbdfblskdfb", a.getString("string", null));
    }

    @Test
    public void testDefaultSettingsArmadilloWithoutPw() {
        //Prepared encrypted data
        MockSharedPref mockSharedPref = new MockSharedPref();
        mockSharedPref.edit()
            .putString("39e3e4f83dda81c44f8a9063196b28b3d5091fca", "bK/e0VSsbCgA2BX3FWbW+b4776Sz6UDU2DHTXvBBGoE=") //prefsalt
            .putString("1cd840c0b8467f9ed9ad22b689ffdc99c2865e75", "AAAAABCvw9ZTgbLV2OHX+4I6p4UHAAAAPoyj677G2UXbhWTNTOQaDj2Uwq0ucDb0ZFU9q5lkF4nQ8LLjsQK0jlUPhvNYLQAaMTm+5SvbF9k+0SIunO7z")
            .putString("68a2a756a680e33f62cce90e4b4565262a834261", "AAAAABDuolICHak8X/oJi9YHoe0tAAAAIVmwvDN1mKfckVzWyyTfjSznPgZH+OzUFjQwilWNmMSIBQ==")
            .putString("9ad191941112df636e2f32d8e49e318b83850ee1", "AAAAABDeQC1toNi7PbWMWeZNtqNzAAAAHpe/fTwV2f0WPJkRinSPMF1SY1TwTWvaWnt4zQl+3w==")
            .putString("df6db071a33bf7c8b3058ebcf30477d48a20c291", "AAAAABA3fcQfvy8tLpyHFkB4h1BeAAAAJVyuO+zkBy7Vjo8i2bKMJg56dBrhbo2PZ+KZ228AR4KRNpAUVDQ=")
            .putString("b9bea5821317ffcc02094ad071cfbc5570d1f9f3", "AAAAABBSpcL48jBGFJwiUFMCGlqVAAAAIa+VFXXJu5mcWHXi/SunQrIpOQLPGRABvk7m9x7DoXFhpA==")
            .commit();

        ArmadilloSharedPreferences a = Armadillo.create(mockSharedPref).encryptionFingerprint(Bytes.parseHex("4b72456178d42f30e43133e8d99006d7").array())
            .password(null).build();

        assertTrue(a.getBoolean("aBoolean", false));
        assertEquals(5623, a.getInt("aInt", -1));
        assertEquals(8281.923452f, a.getFloat("aFloat", 0.0f));
        assertEquals(108731871230172893L, a.getLong("aLong", 0L));
        assertEquals("87adhpn2p807 1807g oasfbdfblskdfb", a.getString("string", null));
    }

    @Test
    public void testAdvancedSettingsArmadilloWithoutPw() {
        //Prepared encrypted data
        MockSharedPref mockSharedPref = new MockSharedPref();
        mockSharedPref.edit()
            .putString("b8cba829d73fda5aa053b891a2152b5492170b6c", "TQLUypXwPfxLIwnCbQk0JPpInq3JK+LZKFuk7f6Swtc=") //prefsalt
            .putString("6d8b460dc8e3b02f339595506f8178ef1748d1d6", "AAAAJRBH76axYBZaxW4ag3aBhN16AAAANc2mf4T76sydYLhiAFlrrk1xLnPnv2oOGCtnl3j33oWq1KBPkZrTv4vrSw0XnkTLQne7BRao")
            .putString("6c565c6422b850ddbb9342e6218e830bd5108c64", "AAAAJRChVXnr7HclFyQB4qws+aS7AAAANan9nf+OiQYFTptiFcjt4Qi9WwLn1ViKKFUX2ZH995pf7FUIDxecX5YnNS57AeNEU7+Ox+B7")
            .putString("c48944c8c4538789e3658bed31daed1bc7193fda", "AAAAJRCbp5MUoUuJJjld+b4z5AFDAAAAT1sPpKBQZka1aDaF9JVr6brBDM2ArTLMrd9wrtjw7qFr6zfkP/1aHI9D+iYf88HLH0u2O1+p4KNxyjMOcz7M9oyZnTB/uCe7uLrPyfWhuSA=")
            .putString("8bc401854ac31419fcd1e0cf06fbbed184e18a9b", "AAAAJRD/glvp3hMqGEAdBZgXDQBKAAAAOfw9Envt59URR07cug2zMAongnHPr5UOgIjt6bN0us0b5WKAI461va4vVCGuI6ptSm0s70PX+2j1Zw==")
            .putString("02716c97bbf042ad3c7dc13d7b6adfd72ade020c", "AAAAJRBkuTLEYR2CBKGM7muMG+clAAAAXR2bNhsrc87UN5sSBt4vCVoBRFIpnNknnI9GAxm5PkzKRJK4hGAQ+5kz5vdVQ4vBo3LhmwbZ2IIGciNIv6idwVqvn2/1AdGu1QVbjb5xDNLidRL9iPTozF0u7D8C4g==")
            .putString("757e7984cd9375edba2d90bc24da5e779aa0e847", "AAAAJRAepZrliCSOu0/0EXtGI7jeAAAAMmCrX02Lg2GV1g2f/50v0cmVIDuVHf1tpDUHjmOJOpEHScSZyTsG3JrgfqO94dzugLI5")
            .commit();

        ArmadilloSharedPreferences a = Armadillo.create(mockSharedPref)
            .encryptionFingerprint(Bytes.parseHex("6894964e2be3b5aaed5ca8c2724f4915").array())
            .compress()
            .cryptoProtocolVersion(37)
            .contentKeyDigest(Bytes.parseHex("f64838a5101258f4432251cd6f0c894f").array())
            .supportVerifyPassword(true)
            .keyStretchingFunction(new PBKDF2KeyStretcher(100, null))
            .password(null).build();

        assertTrue(a.getBoolean("aBoolean", false));
        assertEquals(5623, a.getInt("aInt", -1));
        assertEquals(8281.923452f, a.getFloat("aFloat", 0.0f));
        assertEquals(108731871230172893L, a.getLong("aLong", 0L));
        assertEquals("87adhpn2p807 1807g oasfbdfblskdfb", a.getString("string", null));
    }

    @Test
    public void testAdvancedSettingsArmadilloWithPw() {
        //Prepared encrypted data
        MockSharedPref mockSharedPref = new MockSharedPref();
        mockSharedPref.edit()
            .putString("64afd9add29b4d96a0de5abd185953b9c91d4f36", "zYE80jvh1tmjW7Bpn+BRp0/Wa6+8HaCs60sdvt7PiBE=") //prefsalt
            .putString("b67f28401fb4fa62cd8de0557f54acec7d96f7a2", "AAtqkxCGZHKX89UcVBPlAVfTQlwOAAAAMvQfKzpTpuUqweKMjiEUOgC/GoBqCBtfrtbNj0obirHwiiMt3gf8jSmE91TU9Y0WCIVJ")
            .putString("1f0d72ba500e2a0e77336a949383e70bbdca2bba", "AAtqkxBgtzP8XJl5uOuRcJUg4C79AAAANbFckgGUnRAXojIznCPEC9FGrB/WNS83xDrnJTWQfQ/J1shDa5MJ2rKCsgk6eMLDp3on6R60")
            .putString("60c9f07be5b05a55cd46ad1fe09246165f02b41e", "AAtqkxCdocGot+75S1qSYzSF9V3yAAAAOZz6Y5N3kgByc2u/GATZbNvrSgFNM20XHezfjrbRhaEPdVUdru0JgGgkektp1O3oWi2ErmKkNwVDHg==")
            .putString("cfd8b81ffb78750ab1439767319303d3e6704051", "AAtqkxDwmBR/WBjPbMibmi9yYyQ4AAAAT4N4s8PpZ37DEAzJumQhuqjqbsPEdL729Od2OJd00aOiKOSGgGnPuSKrhb4Lf1Z9+zKfmPD74AiuWT7AqmltJR76w1kPcz2YSZn5UeL0pvE=")
            .putString("14925730b8f9d0c2454128af17e2aa2f6a0c6a1f", "AAtqkxCcirf6XnCC4BhOboLpn4OFAAAANYwGOwH6/SlVQrzd1ion6A4ER86gxQSYWK2HkYOE7kUfF6TPpdAs8wTG317QDIVjfqkaJ3sh")
            .putString("c91939d3b90a63143989d66cdee2c01575cde9b9", "AAtqkxCMoaRjFk+Ih+jH3/OgKglaAAAAXRw/SejvEwJkxmDOpdQe/yX8hICuGAvbKCauI/ei6yJSckU9ULUhz+9n6x7+/yc6NuChHFaSN8SaL9Cv7Q9uv15LkrDgTJUQEivC/gcXBioloA9eU+3JalVmLwxnug==")
            .commit();

        ArmadilloSharedPreferences a = Armadillo.create(mockSharedPref)
            .encryptionFingerprint(Bytes.parseHex("385b2db3ca08845c52bc86b3d06ee903").array())
            .compress()
            .cryptoProtocolVersion(748179)
            .contentKeyDigest(Bytes.parseHex("f31058e8b67ed2198a8366733b7b039b").array())
            .supportVerifyPassword(true)
            .keyStretchingFunction(new FastKeyStretcher())
            .password("乨ØǲǲɻaД\u058DAאaABB12\u08A1A2$_".toCharArray()).build();

        assertTrue(a.getBoolean("aBoolean", false));
        assertEquals(5623, a.getInt("aInt", -1));
        assertEquals(8281.923452f, a.getFloat("aFloat", 0.0f));
        assertEquals(108731871230172893L, a.getLong("aLong", 0L));
        assertEquals("87adhpn2p807 1807g oasfbdfblskdfb", a.getString("string", null));
    }

    @Test
    @Ignore
    public void generateTestData() {
        MockSharedPref mockSharedPref = new MockSharedPref();
        ArmadilloSharedPreferences a = Armadillo.create(mockSharedPref)
            .encryptionFingerprint(Bytes.parseHex("385b2db3ca08845c52bc86b3d06ee903").array())
            .compress()
            .cryptoProtocolVersion(748179)
            .contentKeyDigest(Bytes.parseHex("f31058e8b67ed2198a8366733b7b039b").array())
            .supportVerifyPassword(true)
            .keyStretchingFunction(new FastKeyStretcher())
            .password("乨ØǲǲɻaД\u058DAאaABB12\u08A1A2$_".toCharArray()).build();

        a.edit()
            .putInt("aInt", 5623)
            .putBoolean("aBoolean", true)
            .putFloat("aFloat", 8281.923452f)
            .putLong("aLong", 108731871230172893L)
            .putString("string", "87adhpn2p807 1807g oasfbdfblskdfb")
            .commit();

        for (Map.Entry<String, ?> stringEntry : mockSharedPref.getAll().entrySet()) {
            System.out.println(".putString(\"" + stringEntry.getKey() + "\", \"" + stringEntry.getValue() + "\")");
        }
    }
}
