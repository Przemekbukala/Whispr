package com.whispr.securechat.security;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import static com.whispr.securechat.common.Constants.RSA_ALGORITHM;

public class RSAEncryptionUtil {
    public static KeyPair generateRSAKeyPair() throws Exception {
        // Generowanie pary kluczy RSA
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            System.out.println("RSA KeyPair generation failed");
            return null;
        }
    }
    public static String encrypt(byte[] data, PublicKey publicKey) throws Exception {
        // Szyfrowanie danych kluczem publicznym RSA
        Cipher  c =Cipher.getInstance(RSA_ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypt_data =c.doFinal(data);
        return Base64.getEncoder().encodeToString(encrypt_data); // Zwróci zaszyfrowane dane
    }

    public static String decrypt(String encryptedData, PrivateKey privateKey) throws Exception {
        // Deszyfrowanie danych kluczem prywatnym RSA
        Cipher  c =Cipher.getInstance(RSA_ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decrypt_data =c.doFinal(encryptedBytes);
        return new String(decrypt_data); // Zwróci odszyfrowane dane
    }

    public static PublicKey decodePublicKey(String encodedPublicKey) throws Exception {
        byte[] publicKeyData = Base64.getDecoder().decode(encodedPublicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyData);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        // Deszyfrowanie danych kluczem prywatnym RSA
        Cipher c = Cipher.getInstance(RSA_ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, privateKey);
        return c.doFinal(encryptedData); // Zwraca odszyfrowane bajty
    }


    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher c = Cipher.getInstance(RSA_ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, publicKey);
        return c.doFinal(data);
    }

    public static boolean isBase64(String data) {
        try {
            Base64.getDecoder().decode(data);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }


}