package com.github.rusakovichma.security.aes.cbc;

import com.github.rusakovichma.security.aes.cbc.service.DecryptService;
import com.github.rusakovichma.security.aes.cbc.settings.SettingsContainer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TamperingAttack {

    private final DecryptService decryptService = SettingsContainer.DECRYPT_SERVICE;

    //Text: {"id": 12345, "balance": 200}
    //BxROBBxG/SesEslIqX7Kz3PVXBKOWuPYh4iDJjLxwys=
    //Text: {"id": 12345, "balance": 900}
    //BxROBBxG/SesEslIqX7KzxWjHN49c/6nDx7fRKIzsAU=
    @Test
    void  encryptedDataTamperingAttack() throws Exception{
        //encrypted - {"id": 12345, "balance": 200}
        String encryptedPrimary = "BxROBBxG/SesEslIqX7Kz3PVXBKOWuPYh4iDJjLxwys=";

        String encryptedModified = encryptedPrimary.replace("3PVXBKOWuPYh4iDJjLxwys=", "xWjHN49c/6nDx7fRKIzsAU=");

        //result - {"id": 12345, "balance": 900}
        String msg = decryptService.decrypt(encryptedModified);
        assertEquals("{\"id\": 12345, \"balance\": 900}", msg);
    }


}
