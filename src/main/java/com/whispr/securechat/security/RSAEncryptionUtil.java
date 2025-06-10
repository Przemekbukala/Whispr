package com.whispr.securechat.security;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import static com.whispr.securechat.common.Constants.RSA_ALGORITHM;
// Importy dla exceptionów

public class RSAEncryptionUtil {
    // Zmienne: brak zmiennych instancyjnych, metody statyczne

    public static KeyPair generateRSAKeyPair() throws Exception {
        // Generowanie pary kluczy RSA
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            System.out.println("RSA KeyPair generation failed");
            return null;
        }
    }
    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        // Szyfrowanie danych kluczem publicznym RSA
        Cipher  c =Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypt_data =c.doFinal(data);
        return encrypt_data; // Zwróci zaszyfrowane dane
    }

    public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        // Deszyfrowanie danych kluczem prywatnym RSA
        Cipher  c =Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypt_data =c.doFinal(encryptedData);
//        System.out.println(new String(decrypt_data));  // zwraca prawdiłowy odkodowany text.
        return decrypt_data; // Zwróci odszyfrowane dane
    }
    public static String encodeToString(byte[] key_in_byte){
       return Base64.getEncoder().encodeToString(key_in_byte);
    }


    public static PublicKey decodePublicKey(String encodedPublicKey) throws Exception {
        byte[] publicKeyData = Base64.getDecoder().decode(encodedPublicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyData);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePublic(spec);
    }



    public static void main (String[] args) {
//        try{
//            KeyPair key_pair = generateRSAKeyPair();
//            String publicKeyString = Base64.getEncoder().encodeToString(key_pair.getPublic().getEncoded());
//            String privateKeyString = Base64.getEncoder().encodeToString(key_pair.getPrivate().getEncoded());
//            System.out.println("Public Key: " + publicKeyString);
//            System.out.println("Private Key: " + publicKeyString);
//            String testowy_string=new String("testowanie działanai encrypcji");
//            byte[] encypted_data= encrypt(testowy_string.getBytes(),key_pair.getPublic());
//            decrypt(encypted_data,key_pair.getPrivate());
//        }catch(Exception e){
//            e.printStackTrace();
//        }
    }



}