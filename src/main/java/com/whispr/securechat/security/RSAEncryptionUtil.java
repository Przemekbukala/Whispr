package com.whispr.securechat.security;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static com.whispr.securechat.common.Constants.RSA_ALGORITHM;

/**
 * A utility class for RSA asymmetric cryptographic operations.
 * It provides methods for generating RSA key pairs, encoding/decoding keys,
 * and encrypting/decrypting data.
 * Used primarily for securely exchanging symmetric keys.
 */
public class RSAEncryptionUtil {

    /**
     * Generates a new RSA key pair with a key size of 2048 bits.
     *
     * @return A {@link KeyPair} containing a public and private key, or null if generation fails.
     */
    public static KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            System.out.println("RSA KeyPair generation failed");
            return null;
        }
    }

    /**
     * Decodes a Base64 encoded public key string into a PublicKey object.
     *
     * @param encodedPublicKey The Base64 string representation of the public key.
     * @return A {@link PublicKey} object.
     * @throws Exception if the key decoding or instantiation fails.
     */
    public static PublicKey decodePublicKey(String encodedPublicKey) throws Exception {
        byte[] publicKeyData = Base64.getDecoder().decode(encodedPublicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyData);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    /**
     * Decrypts data using an RSA private key.
     *
     * @param encryptedData The byte array of the encrypted data.
     * @param privateKey    The {@link PrivateKey} to use for decryption.
     * @return A byte array containing the original plaintext data.
     * @throws Exception if the decryption process fails.
     */
    public static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        // Deszyfrowanie danych kluczem prywatnym RSA
        Cipher c = Cipher.getInstance(RSA_ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, privateKey);
        return c.doFinal(encryptedData); // Zwraca odszyfrowane bajty
    }

    /**
     * Encrypts data using an RSA public key.
     *
     * @param data      The plaintext data to encrypt.
     * @param publicKey The {@link PublicKey} to use for encryption.
     * @return A byte array containing the encrypted ciphertext.
     * @throws Exception if the encryption process fails.
     */
    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher c = Cipher.getInstance(RSA_ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, publicKey);
        return c.doFinal(data);
    }

    /**
     * Checks if a given string is a valid Base64 encoded string.
     *
     * @param data The string to check.
     * @return true if the string is valid Base64, false otherwise.
     */
    public static boolean isBase64(String data) {
        try {
            Base64.getDecoder().decode(data);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }


}