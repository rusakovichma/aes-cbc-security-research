package com.github.rusakovichma.security.aes.cbc.service.impl;

import com.github.rusakovichma.security.aes.cbc.SensitiveDataCrypto;
import com.github.rusakovichma.security.aes.cbc.service.ServiceWithDecryption;

import javax.crypto.BadPaddingException;

public class ServiceWithDecryptionImpl implements ServiceWithDecryption {

    private final SensitiveDataCrypto crypto;

    public ServiceWithDecryptionImpl(String algorithm, String transformation, String key, String vector) {
        this.crypto = new SensitiveDataCrypto(algorithm, transformation, key, vector);
    }

    @Override
    public void methodWithDecryption(String encrypted) throws BadPaddingException{
        try {
            crypto.decrypt(encrypted);
        }catch(Exception ex){
            Throwable cause = ex.getCause();
            if (cause != null && cause instanceof BadPaddingException){
                throw (BadPaddingException) cause;
            }
        }
    }

    @Override
    public void methodWithDecryptionWithIV(String encrypted, byte[] iv) throws BadPaddingException{
        try {
            crypto.decryptWithIV(encrypted, iv);
        }catch(Exception ex){
            Throwable cause = ex.getCause();
            if (cause != null && cause instanceof BadPaddingException){
                throw (BadPaddingException) cause;
            }
        }
    }

}
