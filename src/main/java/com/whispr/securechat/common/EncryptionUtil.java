package com.whispr.securechat.common;

import com.whispr.securechat.security.AESEncryptionUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * EncryptionUtil class provides a static encryption method.
 */
public class EncryptionUtil {
    /**
     * Decrypts the payload of a received message using the AES key.
     * This method extracts the initialization vector (IV) from the message and uses it along with the  AES key to decrypt the message payload
     * and returns the decrypted content as a string.
     * @param message The encrypted message to decrypt.
     *  @param aesKey AES used to decrypt the message.
     * @return The decrypted payload as a string, or null if decryption fails.
     * @throws RuntimeException If an error occurs during decryption.
     */
    public static String decryptedPayload(Message message, SecretKey aesKey) {
        if (aesKey == null) {
            System.err.println("AES key not established. Cannot decrypt message.");
            return null;
        }
        byte[] ivBytes = message.getEncryptedIv();
        if (ivBytes == null) {
            System.err.println("IV not found in message. Cannot decrypt message.");
            return null;
        }
        IvParameterSpec IV = new IvParameterSpec(ivBytes);
        String decryptedPayload = null;
        try {
            decryptedPayload = AESEncryptionUtil.decrypt(message.getPayload(), aesKey, IV);
        } catch (Exception e) {
            System.err.println("Error during decription " + e.getMessage());
            throw new RuntimeException(e);
        }
        return decryptedPayload;
    }
}
