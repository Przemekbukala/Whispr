package com.whispr.securechat.security;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import static com.whispr.securechat.common.Constants.AES_ALGORITHM;

/**
 * A utility class for AES (Advanced Encryption Standard) cryptographic operations.
 * It provides methods for generating AES keys, encrypting, and decrypting data.
 * This class uses the AES/CBC/PKCS5Padding transformation.
 */
public class AESEncryptionUtil {
    private static final int KEY_LENGTH = 256;

    /**
     * Generates a new 256-bit AES secret key.
     *
     * @return A {@link SecretKey} for AES encryption, or null if key generation fails.
     */
    public static SecretKey generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(KEY_LENGTH);
            return keyGen.generateKey();
        } catch (Exception e) {
            System.out.println("AES Key generation failed");
            return null;
        }
    }

    /**
     * Generates a new 16-byte Initialization Vector (IV) for use with CBC mode.
     * An IV is crucial for security as it ensures that encrypting the same plaintext multiple times results in different ciphertexts.
     * @return A new {@link IvParameterSpec}.
     */
    public static IvParameterSpec  generateIVParameterSpec() {
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



    /**
     * Encrypts the given byte array using the provided AES key and IV.
     * @param data The plaintext data to encrypt.
     * @param aesKey The {@link SecretKey} to use for encryption.
     * @param iv The {@link IvParameterSpec} for CBC mode.
     * @return A Base64-encoded string representing the encrypted data.
     * @throws Exception if encryption fails.
     */
    public static String encrypt(byte[] data, SecretKey aesKey, IvParameterSpec iv) throws Exception {
        // Szyfrowanie danych
        Cipher  c =Cipher.getInstance(AES_ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, aesKey,iv);
        return Base64.getEncoder().encodeToString(c.doFinal(data));
    }

    /**
     * Decrypts a Base64-encoded string using the provided AES key and IV.
     * @param encryptedData The Base64-encoded ciphertext.
     * @param aesKey The {@link SecretKey} that was used for encryption.
     * @param iv The {@link IvParameterSpec} that was used for encryption.
     * @return A string containing the decrypted plaintext.
     * @throws Exception if decryption fails (e.g., incorrect key, IV, or corrupted data).
     */
    public static String decrypt(String encryptedData, SecretKey aesKey, IvParameterSpec iv) throws Exception {
        // Deszyfrowanie danych
        Cipher  c =Cipher.getInstance(AES_ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, aesKey,iv);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decrypt_data =c.doFinal(encryptedBytes);
        return new String(decrypt_data); // Zwróci odszyfrowane dane
    }

}
