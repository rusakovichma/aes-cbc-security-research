package com.github.rusakovichma.security.aes.cbc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;


class SensitiveDataCryptoTest {

    private static final String ALG_DEFAULT = "AES";
    private static final String TRFN_DEFAULT = "AES/CBC/PKCS5Padding";
    private static final String PK_DEFAULT = "kdhfrjuqodncgtyuidnxbdteoglanzye";
    private static final String IV_DEFAULT = "1234567890123456";

    private SensitiveDataCrypto cryptoAesCbc = new SensitiveDataCrypto(ALG_DEFAULT,
            TRFN_DEFAULT,
            PK_DEFAULT,
            IV_DEFAULT
    );

    private static final String GCM_ALG_DEFAULT = "AES";
    private static final String GCM_TRFN_DEFAULT = "AES/GCM/NoPadding";
    private static final String GCM_PK_DEFAULT = "kdhfrjuqodncgtyuidnxbdteoglanzye";
    private static final String GCM_IV_DEFAULT = "1234567890123456";

    private GcmSensitiveDataCrypto cryptoAesGcm = new GcmSensitiveDataCrypto(GCM_ALG_DEFAULT,
            GCM_TRFN_DEFAULT,
            GCM_PK_DEFAULT,
            GCM_IV_DEFAULT
    );

   @Test
    void aesCbcEncodeTest() throws Exception{
        String msg = "{\"id\": 12345, \"balance\": 200}";
        String encrypted = cryptoAesCbc.encrypt(msg);
        assertEquals("BxROBBxG/SesEslIqX7Kz3PVXBKOWuPYh4iDJjLxwys=", encrypted);
    }

    @Test
    void aesCbcDecodeTest() throws Exception{
        String msg = cryptoAesCbc.decrypt("BxROBBxG/SesEslIqX7Kz3PVXBKOWuPYh4iDJjLxwys=");
        assertEquals("{\"id\": 12345, \"balance\": 200}", msg);
    }

    @Test
    void aesGcmEncodeTest() throws Exception{
        String msg = "{\"id\": 12345, \"balance\": 200}";
        String encrypted = cryptoAesGcm.encrypt(msg);
        assertEquals("MUgze5u/EX0UrepED8ATABpLtojXptr/qzOhoQcMmFla0ZDBVVoZ4G5N5aNp", encrypted);
    }

    @Test
    void aesGcmDecodeTest() throws Exception{
        String msg = "MUgze5u/EX0UrepED8ATABpLtojXptr/qzOhoQcMmFla0ZDBVVoZ4G5N5aNp";
        assertEquals("{\"id\": 12345, \"balance\": 200}", cryptoAesGcm.decrypt(msg));
    }


}