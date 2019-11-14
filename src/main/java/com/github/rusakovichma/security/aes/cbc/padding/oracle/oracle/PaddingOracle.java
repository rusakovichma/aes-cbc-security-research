package com.github.rusakovichma.security.aes.cbc.padding.oracle.oracle;

import com.github.rusakovichma.security.aes.cbc.padding.oracle.block.EncryptedBlock;
import com.github.rusakovichma.security.aes.cbc.service.ServiceWithDecryption;

import javax.crypto.BadPaddingException;
import java.util.Base64;


/**
 * This is a padding oracle. It answers just one question - is the encryption structure correctly padded or not.
 */
public enum PaddingOracle {
    INSTANCE;

    /**
     * Returns true is the encrypted text is correctly padded.
     *
     * @param encrypted
     * @return
     */

    public boolean isCorrectlyPadded(EncryptedBlock encrypted, ServiceWithDecryption decryptService) {
        try {
            decryptService.methodWithDecryptionWithIV(
                    Base64.getEncoder().encodeToString(encrypted.encrypted), encrypted.iv);
        } catch(BadPaddingException exc) {
                return false;
        }
        return true;
    }

}


