package com.whispr.securechat.security;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import static com.whispr.securechat.common.Constants.AES_ALGORITHM;

public class AESEncryptionUtil {
    private static final int KEY_LENGTH = 256;
    public static SecretKey generateAESKey() throws Exception {
        // Tworzenie klucza AES
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(KEY_LENGTH);
            return keyGen.generateKey();
        } catch (Exception e) {
            System.out.println("AES Key generation failed");
            return null;
        }
    }
    public static IvParameterSpec  generateIVParameterSpec() throws Exception {
        try {
            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);
            return new IvParameterSpec(ivBytes);
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }




    public static String encrypt(byte[] data, SecretKey aesKey, IvParameterSpec iv) throws Exception {
        // Szyfrowanie danych
        Cipher  c =Cipher.getInstance(AES_ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, aesKey,iv);
//        return ; // Zwróci zaszyfrowane dane
        return Base64.getEncoder().encodeToString(c.doFinal(data));
    }
    public static String decrypt(String encryptedData, SecretKey aesKey, IvParameterSpec iv2) throws Exception {
        // Deszyfrowanie danych
        Cipher  c =Cipher.getInstance(AES_ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, aesKey,iv2);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decrypt_data =c.doFinal(encryptedBytes);
        return new String(decrypt_data); // Zwróci odszyfrowane dane
    }

}
