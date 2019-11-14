package com.github.rusakovichma.security.aes.cbc.service;

import javax.crypto.BadPaddingException;

public interface ServiceWithDecryption {

    public void methodWithDecryption(String encrypted) throws BadPaddingException;

    public void methodWithDecryptionWithIV(String encrypted, byte[] iv) throws BadPaddingException;

}
