package com.github.rusakovichma.security.aes.cbc.padding.oracle.decrypt;

import javax.crypto.BadPaddingException;

import com.github.rusakovichma.security.aes.cbc.padding.oracle.block.EncryptedBlock;
import com.github.rusakovichma.security.aes.cbc.padding.oracle.oracle.PaddingOracle;
import com.github.rusakovichma.security.aes.cbc.service.ServiceWithDecryption;
import com.github.rusakovichma.security.aes.cbc.padding.oracle.block.EncryptionConstants;

/**
 * This utility tries to methodWithDecryption the last plain text block of the encrypted text. If the encrypted text has only one
 * block the utility is clever enough to use the IV for the padding oracle attack.
 */
public enum Decryptor
{
    INSTANCE;

    /**
     * Decrypts all of the blocks and strips the PKCS7 padding.
     * 
     * @param encrypted
     * @return
     */
    public byte[] decryptAllBlocks(EncryptedBlock encrypted, ServiceWithDecryption crypto)
    {
        byte[] plainText = new byte[encrypted.getNumberOfBlocks() * EncryptionConstants.CIPHER_BLOCK_SIZE];

        for (int blockNum = encrypted.getNumberOfBlocks(); blockNum >= 1; blockNum--)
        {
            byte[] decryptedBlock = Decryptor.INSTANCE.decryptLastBlock(encrypted, crypto);
            if (blockNum > 1)
                encrypted = encrypted.withoutLastBlock();
            System.arraycopy(decryptedBlock, 0, plainText, (blockNum - 1) * EncryptionConstants.CIPHER_BLOCK_SIZE, EncryptionConstants.CIPHER_BLOCK_SIZE);
        }

        try
        {
            plainText = PKCS7Util.INSTANCE.stripPadding(plainText);
        }
        catch(BadPaddingException e)
        {
            // should not happen
            throw new RuntimeException(e);
        }

        return plainText;
    }

    /**
     * Decrypts the last block of the encryption sequence by using a padding Oracle.
     * 
     * @param encrypted
     *            the encrypted text
     * @return the decrypted last block of the text including the PKCS7 padding.
     */
    public byte[] decryptLastBlock(EncryptedBlock encrypted, ServiceWithDecryption crypto)
    {
        // we will store the decrypted bytes here
        byte decryptedBlock[] = new byte[EncryptionConstants.CIPHER_BLOCK_SIZE];
        // clone the encrypted struct so that we can easily modify it
        EncryptedBlock encStruct = EncryptedBlock.create(encrypted);

        byte[] bytesToPlay = getBytesToPlay(encStruct);
        // we start at the last byte of the last but one block, this might be the iv as well
        int byteToRotateIdx = bytesToPlay.length > EncryptionConstants.CIPHER_BLOCK_SIZE ? bytesToPlay.length - EncryptionConstants.CIPHER_BLOCK_SIZE - 1
                        : EncryptionConstants.CIPHER_BLOCK_SIZE - 1;

        for (int decryptedByteIdx = decryptedBlock.length - 1; decryptedByteIdx >= 0; decryptedByteIdx--)
        {
            int fakePaddingByte = decryptedBlock.length - decryptedByteIdx;// eg, idx 15 -> padding -> 0x01

            // the guess for the last one is, e.g. b ^ 0x01 ^ i, where i e [0;255]
            // when i hits the correct plain text we will have correct padding
            byte guessBase = (byte)((bytesToPlay[byteToRotateIdx] ^ fakePaddingByte) & 0xff);
            // used to resolve ambiguities,
            // see here: http://crypto.stackexchange.com/questions/40800/is-the-padding-oracle-attack-deterministic
            int ambiguityByte = 0;
            boolean bAlreadyHit = false;

            for (int i = 0; i < 255; i++)
            {
                bytesToPlay[byteToRotateIdx] = (byte)((guessBase ^ i) & 0xff);

                if (PaddingOracle.INSTANCE.isCorrectlyPadded(encStruct, crypto))
                {
                    if (bAlreadyHit)
                    {
                        i = 0;
                        bytesToPlay[byteToRotateIdx - 1] = (byte)(ambiguityByte & 0xff);
                        bAlreadyHit = false;
                        ambiguityByte++;
                        continue;
                    }

                    bAlreadyHit = true;
                    decryptedBlock[decryptedByteIdx] = (byte)(i & 0xff);

                }
            }

            // "fix" the other bytes so that we can move on, clone the original thingy
            encStruct = EncryptedBlock.create(encrypted);
            bytesToPlay = getBytesToPlay(encStruct);

            byteToRotateIdx--;
            // now we have to adjust all the bytes in the 'right' direction

            int fixStartByteIdx = byteToRotateIdx + 1;
            int fixEndByteIdx = (((byteToRotateIdx / EncryptionConstants.CIPHER_BLOCK_SIZE) * EncryptionConstants.CIPHER_BLOCK_SIZE) + EncryptionConstants.CIPHER_BLOCK_SIZE - 1);

            for (int idx = fixStartByteIdx; idx <= fixEndByteIdx; idx++)
            {
                int decryptedIdx = idx % EncryptionConstants.CIPHER_BLOCK_SIZE;
                byte fakeByte = (byte)((bytesToPlay[idx] ^ (fakePaddingByte + 1) ^ decryptedBlock[decryptedIdx])
                                & 0xff);
                bytesToPlay[idx] = fakeByte;
            }
            // break;
        }

        return decryptedBlock;

    }

    private static byte[] getBytesToPlay(EncryptedBlock enc)
    {
        return enc.getNumberOfBlocks() > 1 ? enc.encrypted : enc.iv;
    }
}
