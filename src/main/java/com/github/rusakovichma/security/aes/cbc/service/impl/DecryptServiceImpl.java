package com.github.rusakovichma.security.aes.cbc.service.impl;

import com.github.rusakovichma.security.aes.cbc.SensitiveDataCrypto;
import com.github.rusakovichma.security.aes.cbc.service.DecryptService;

public class DecryptServiceImpl implements DecryptService {

    private final SensitiveDataCrypto crypto;

    public DecryptServiceImpl(String algorithm, String transformation, String key, String vector) {
        this.crypto = new SensitiveDataCrypto(algorithm, transformation, key, vector);
    }

    @Override
    public String decrypt(String plainText) {
        return crypto.decrypt(plainText);
    }

}
