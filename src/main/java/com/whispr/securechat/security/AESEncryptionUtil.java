package com.whispr.securechat.security;

import javax.crypto.SecretKey;
import javax.crypto.Cipher;
// Importy dla exceptionów

public class AESEncryptionUtil {
    // Zmienne: brak zmiennych instancyjnych, metody statyczne lub instancja z kluczem AES
    // Jeśli klucz AES jest unikalny dla każdej sesji klienta, to każda instancja ClientHandler będzie miała swój SecretKey.
    // Jeśli chcesz mieć to jako utility static, to klucz AES będzie przekazywany do metod.
    // Przyjmujemy na razie opcję utility statycznego, wymagającego przekazywania klucza.

    public static SecretKey generateAESKey() throws Exception {
        // Tworzenie klucza AES
        return null; // Zwróci wygenerowany klucz
    }

    public static byte[] encrypt(byte[] data, SecretKey aesKey) throws Exception {
        // Szyfrowanie danych
        return null; // Zwróci zaszyfrowane dane
    }

    public static byte[] decrypt(byte[] encryptedData, SecretKey aesKey) throws Exception {
        // Deszyfrowanie danych
        return null; // Zwróci odszyfrowane dane
    }
}
