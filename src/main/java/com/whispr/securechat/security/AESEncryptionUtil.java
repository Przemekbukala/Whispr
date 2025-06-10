package com.whispr.securechat.security;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.util.Arrays;
import java.util.Base64;

import static com.whispr.securechat.common.Constants.AES_ALGORITHM;
import static com.whispr.securechat.common.Constants.RSA_ALGORITHM;
// Importy dla exceptionów

public class AESEncryptionUtil {
    // Zmienne: brak zmiennych instancyjnych, metody statyczne lub instancja z kluczem AES
    // Jeśli klucz AES jest unikalny dla każdej sesji klienta, to każda instancja ClientHandler będzie miała swój SecretKey.
    // Jeśli chcesz mieć to jako utility static, to klucz AES będzie przekazywany do metod.
    // Przyjmujemy na razie opcję utility statycznego, wymagającego przekazywania klucza.
    private static final int KEY_LENGTH = 256;
    public static SecretKey generateAESKey() throws Exception {
        // Tworzenie klucza AES
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            return secretKey;
        } catch (Exception e) {
            System.out.println("AES Key generation failed");
            return null;
        }
    }

    public static byte[] encrypt(byte[] data, SecretKey aesKey) throws Exception {
        // Szyfrowanie danych
        Cipher  c =Cipher.getInstance(AES_ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypt_data =c.doFinal(data);
        return encrypt_data; // Zwróci zaszyfrowane dane
    }

    public static byte[] decrypt(byte[] encryptedData, SecretKey aesKey) throws Exception {
        // Deszyfrowanie danych
        Cipher  c =Cipher.getInstance(AES_ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypt_data =c.doFinal(encryptedData);
        System.out.println(new String(decrypt_data));  // zwraca prawdiłowy odkodowany text.
        return decrypt_data; // Zwróci odszyfrowane dane

    }
    public static void main (String[] args) {
        try{
            SecretKey secretKey = generateAESKey();
            String secret_key = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            System.out.println("Secret Key: " + secret_key);

            String testowy_string=new String("testowanie działanai encrypcji");
            byte[] encypted_data= encrypt(testowy_string.getBytes(),secretKey);
            byte[] decrepted_data=decrypt(encypted_data,secretKey);
            System.out.println(new String(decrepted_data));

        }catch(Exception e){
            e.printStackTrace();
        }
    }

}
