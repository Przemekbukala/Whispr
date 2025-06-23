package com.whispr.securechat.security;

import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class RSAEncryptionUtilTest {

    @Test
    void testGenerateRSAKeyPair() {
        KeyPair keyPair = RSAEncryptionUtil.generateRSAKeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("RSA", keyPair.getPublic().getAlgorithm());
    }

    @Test
    void testEncryptDecryptSymmetry() throws Exception {
        KeyPair keyPair = RSAEncryptionUtil.generateRSAKeyPair();
        byte[] originalData = "This is a test string for RSA.".getBytes();

        byte[] encryptedData = RSAEncryptionUtil.encryptRSA(originalData, keyPair.getPublic());
        assertNotNull(encryptedData);
        assertNotEquals(originalData, encryptedData);

        byte[] decryptedData = RSAEncryptionUtil.decryptRSA(encryptedData, keyPair.getPrivate());
        assertArrayEquals(originalData, decryptedData, "Decrypted data should match the original data.");
    }

    @Test
    void testPublicKeyEncodingAndDecoding() throws Exception {
        KeyPair keyPair = RSAEncryptionUtil.generateRSAKeyPair();
        assertNotNull(keyPair);
        PublicKey originalPublicKey = keyPair.getPublic();

        String encodedKey = Base64.getEncoder().encodeToString(originalPublicKey.getEncoded());
        PublicKey decodedPublicKey = RSAEncryptionUtil.decodePublicKey(encodedKey);

        assertEquals(originalPublicKey, decodedPublicKey, "Decoded public key should be identical to the original.");
    }

    @Test
    void testIsBase64() {
        assertTrue(RSAEncryptionUtil.isBase64("SGVsbG8gV29ybGQ="), "Should correctly identify a valid Base64 string with padding.");
        assertTrue(RSAEncryptionUtil.isBase64("SGVsbG8gV29ybGQ"), "Should identify a valid Base64 string even without padding, due to lenient decoder.");
        assertFalse(RSAEncryptionUtil.isBase64("This is not valid!@#"), "Should correctly identify a string with non-Base64 characters.");
    }
}