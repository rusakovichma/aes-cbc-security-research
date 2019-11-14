package com.github.rusakovichma.security.aes.cbc.service.impl;

import com.github.rusakovichma.security.aes.cbc.SensitiveDataCrypto;
import com.github.rusakovichma.security.aes.cbc.service.EncryptService;

public class EncryptServiceImpl implements EncryptService {

    private final SensitiveDataCrypto crypto;

    public EncryptServiceImpl(String algorithm, String transformation, String key, String vector) {
        this.crypto = new SensitiveDataCrypto(algorithm, transformation, key, vector);
    }

    @Override
    public String encrypt(String plainText) {
        return crypto.encrypt(plainText);
    }
}
