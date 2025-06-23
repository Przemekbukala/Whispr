package com.whispr.securechat.security;

import org.junit.jupiter.api.Test;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import static org.junit.jupiter.api.Assertions.*;

class AESEncryptionUtilTest {

    @Test
    void testGenerateAESKey() {
        SecretKey key = AESEncryptionUtil.generateAESKey();
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length, "AES key should be 256 bits (32 bytes).");
    }

    @Test
    void testGenerateIVParameterSpec() {
        IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
        assertNotNull(iv);
        assertEquals(16, iv.getIV().length, "IV should be 16 bytes for AES/CBC.");
    }

    @Test
    void testEncryptDecryptSymmetry() throws Exception {
        SecretKey key = AESEncryptionUtil.generateAESKey();
        IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
        String originalText = "This is a secret message for testing AES encryption.";

        String encryptedText = AESEncryptionUtil.encrypt(originalText.getBytes(), key, iv);
        assertNotNull(encryptedText);
        assertNotEquals(originalText, encryptedText);

        String decryptedText = AESEncryptionUtil.decrypt(encryptedText, key, iv);
        assertEquals(originalText, decryptedText, "Decrypted text should match the original text.");
    }

    @Test
    void testDecryptWithWrongKeyFails() throws Exception {
        SecretKey key1 = AESEncryptionUtil.generateAESKey();
        SecretKey key2 = AESEncryptionUtil.generateAESKey();
        IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
        String originalText = "Some data to encrypt.";

        String encryptedText = AESEncryptionUtil.encrypt(originalText.getBytes(), key1, iv);

        assertThrows(Exception.class, () -> {
            AESEncryptionUtil.decrypt(encryptedText, key2, iv);
        }, "Decryption with a different key should throw an exception.");
    }

    @Test
    void testEncryptWithNullData() {
        SecretKey key = AESEncryptionUtil.generateAESKey();
        IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();

        assertThrows(IllegalArgumentException.class, () -> {
            AESEncryptionUtil.encrypt(null, key, iv);
        }, "Encrypting null data should throw an exception.");
    }
}