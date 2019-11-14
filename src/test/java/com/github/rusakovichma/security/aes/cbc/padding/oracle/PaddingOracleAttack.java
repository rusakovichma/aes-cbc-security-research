package com.github.rusakovichma.security.aes.cbc.padding.oracle;

import com.github.rusakovichma.security.aes.cbc.padding.oracle.block.EncryptedBlock;
import com.github.rusakovichma.security.aes.cbc.padding.oracle.decrypt.Decryptor;
import com.github.rusakovichma.security.aes.cbc.service.ServiceWithDecryption;
import com.github.rusakovichma.security.aes.cbc.settings.SettingsContainer;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class PaddingOracleAttack {

    private final ServiceWithDecryption serviceWithDecryption = SettingsContainer.SERVICE_WITH_DECRYPTION;

    @Test
    void  paddingOracleAttackWithKnownIV() {
        //encrypted - {"id": 12345, "balance": 200}
        byte[] encrypted = Base64.getDecoder().decode("BxROBBxG/SesEslIqX7Kz3PVXBKOWuPYh4iDJjLxwys=");
        byte[] iv = "1234567890123456".getBytes();

        EncryptedBlock encryptedBlock = EncryptedBlock.create(iv, encrypted);

        byte[] decrypted = Decryptor.INSTANCE.decryptAllBlocks(encryptedBlock, serviceWithDecryption);
        assertEquals("{\"id\": 12345, \"balance\": 200}", new String(decrypted));
    }

    @Test
    void  paddingOracleAttackUnknownIV() {
        //encrypted - {"id": 12345, "balance": 200}
        byte[] encrypted = Base64.getDecoder().decode("BxROBBxG/SesEslIqX7Kz3PVXBKOWuPYh4iDJjLxwys=");
        byte[] iv = "9999999999999999".getBytes();

        EncryptedBlock encryptedBlock = EncryptedBlock.create(iv, encrypted);

        byte[] decrypted = Decryptor.INSTANCE.decryptAllBlocks(encryptedBlock, serviceWithDecryption);
        assertTrue(new String(decrypted).endsWith("alance\": 200}"));
    }

}
