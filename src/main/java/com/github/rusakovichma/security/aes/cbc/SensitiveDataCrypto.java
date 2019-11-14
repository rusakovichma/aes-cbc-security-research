package com.github.rusakovichma.security.aes.cbc;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SensitiveDataCrypto {

    public static final String CHARSET_DEFAULT = "ASCII";

    private final String charsetName = CHARSET_DEFAULT;

    private final String algorithm;
    private final String transformation;
    private final String key;
    private final String vector;

    public SensitiveDataCrypto(String algorithm, String transformation, String key, String vector) {
        this.algorithm = algorithm;
        this.transformation = transformation;
        this.key = key;
        this.vector = vector;
    }

    private void verifyRequiredPropertiesSet() {
        if (algorithm == null ||
                transformation == null ||
                key == null ||
                vector == null ||
                charsetName == null) {
            throw new RuntimeException("Not all required properties for SensitiveDataCrypto are set");
        }
    }

    public String decryptWithIV(String encryptedText, byte[] iv) {
        verifyRequiredPropertiesSet();

        if (encryptedText == null || encryptedText.length() == 0) {
            return "";
        }

        byte[] encryptedTextBytes = Base64.getDecoder().decode(encryptedText);
        byte[] textBytes;
        try {
            textBytes = executeCryptoActionWithIV(encryptedTextBytes, iv, Cipher.DECRYPT_MODE);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String result = new String(textBytes, Charset.forName(charsetName));
        return result;
    }

    public String decrypt(String encryptedText) {
        verifyRequiredPropertiesSet();

        if (encryptedText == null || encryptedText.length() == 0) {
            return "";
        }

        byte[] encryptedTextBytes = Base64.getDecoder().decode(encryptedText);
        byte[] textBytes;
        try {
            textBytes = executeCryptoAction(encryptedTextBytes, Cipher.DECRYPT_MODE);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String result = new String(textBytes, Charset.forName(charsetName));
        return result;
    }


    public String encrypt(String plainText) {
        verifyRequiredPropertiesSet();

        byte[] textBytes = plainText.getBytes(Charset.forName(charsetName));
        byte[] encryptedTextBytes;
        try {
            encryptedTextBytes = executeCryptoAction(textBytes, Cipher.ENCRYPT_MODE);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        byte[] base64 = Base64.getEncoder().encode(encryptedTextBytes);
        String result = new String(base64, Charset.forName(charsetName));
        return result;
    }

    private byte[] executeCryptoAction(byte[] input, int cipherMode) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {
       return  executeCryptoActionWithIV(input, vector.getBytes(Charset.forName(charsetName)), cipherMode);
    }

    private byte[] executeCryptoActionWithIV(byte[] input, byte[] iv, int cipherMode) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {
        byte[] keyBytes = key.getBytes(Charset.forName(charsetName));

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(cipherMode, new SecretKeySpec(keyBytes, algorithm), new IvParameterSpec(iv));

        byte[] result = cipher.doFinal(input);
        return result;
    }

}
