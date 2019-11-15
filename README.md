# Attacks on AES-CBC encryption

## Padding Oracle Attack

The standard implementation of CBC decryption in block ciphers is to decrypt all ciphertext blocks, validate the padding, remove the PKCS7 padding, and return the message's plaintext. If the server returns an "invalid padding" error instead of a generic "decryption failed" error, the attacker can use the server as a padding oracle to decrypt (and sometimes encrypt) messages.

Code example
===============
Full example may be found here: https://github.com/rusakovichma/aes-cbc-security-research/blob/master/src/test/java/com/github/rusakovichma/security/aes/cbc/padding/oracle/PaddingOracleAttack.java


```JAVA
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
```

## Tampering Attack

Code example
===============
Full example may be found here: https://github.com/rusakovichma/aes-cbc-security-research/blob/master/src/test/java/com/github/rusakovichma/security/aes/cbc/TamperingAttack.java


```JAVA
    //Text: {"id": 12345, "balance": 200}
    //BxROBBxG/SesEslIqX7Kz{3PVXBKOWuPYh4iDJjLxwys=}
    //Text: {"id": 12345, "balance": 900}
    //BxROBBxG/SesEslIqX7Kz{xWjHN49c/6nDx7fRKIzsAU=}
    @Test
    void  encryptedDataTamperingAttack() throws Exception{
        //encrypted - {"id": 12345, "balance": 200}
        String encryptedPrimary = "BxROBBxG/SesEslIqX7Kz3PVXBKOWuPYh4iDJjLxwys=";

        String encryptedModified = encryptedPrimary.replace("3PVXBKOWuPYh4iDJjLxwys=", "xWjHN49c/6nDx7fRKIzsAU=");

        //result - {"id": 12345, "balance": 900}
        String msg = decryptService.decrypt(encryptedModified);
        assertEquals("{\"id\": 12345, \"balance\": 900}", msg);
    }
```



