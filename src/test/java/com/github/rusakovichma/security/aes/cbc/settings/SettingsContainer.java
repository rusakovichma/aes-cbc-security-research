package com.github.rusakovichma.security.aes.cbc.settings;

import com.github.rusakovichma.security.aes.cbc.service.DecryptService;
import com.github.rusakovichma.security.aes.cbc.service.ServiceWithDecryption;
import com.github.rusakovichma.security.aes.cbc.service.EncryptService;
import com.github.rusakovichma.security.aes.cbc.service.impl.DecryptServiceImpl;
import com.github.rusakovichma.security.aes.cbc.service.impl.ServiceWithDecryptionImpl;
import com.github.rusakovichma.security.aes.cbc.service.impl.EncryptServiceImpl;

public final class SettingsContainer {

    private SettingsContainer(){
    }

    private static final String ALG_DEFAULT = "AES";
    private static final String TRFN_DEFAULT = "AES/CBC/PKCS5Padding";
    private static final String PK_DEFAULT = "kdhfrjuqodncgtyuidnxbdteoglanzye";
    private static final String IV_DEFAULT = "1234567890123456";




    public static final ServiceWithDecryption SERVICE_WITH_DECRYPTION = new ServiceWithDecryptionImpl(
            SettingsContainer.ALG_DEFAULT,
            SettingsContainer.TRFN_DEFAULT,
            SettingsContainer.PK_DEFAULT,
            SettingsContainer.IV_DEFAULT
    );

    public static final DecryptService DECRYPT_SERVICE = new DecryptServiceImpl(
            SettingsContainer.ALG_DEFAULT,
            SettingsContainer.TRFN_DEFAULT,
            SettingsContainer.PK_DEFAULT,
            SettingsContainer.IV_DEFAULT
    );


    public static final EncryptService ENCRYPT_SERVICE = new EncryptServiceImpl(
            SettingsContainer.ALG_DEFAULT,
            SettingsContainer.TRFN_DEFAULT,
            SettingsContainer.PK_DEFAULT,
            SettingsContainer.IV_DEFAULT
    );

}
