package com.whispr.securechat.common;

public final class Constants { // Klasa finalna, ponieważ to klasa z samymi stałymi
    public static final int SERVER_PORT = 8080; // Przykładowy port
    public static final String AES_ALGORITHM = "AES/ECB/PKCS5Padding"; // Rekomendacja z projektu [cite: 57]
    public static final String RSA_ALGORITHM = "RSA";
    public static final String HASH_ALGORITHM = "BCrypt"; // Lub "BCrypt" [cite: 65]
    public static final String DB_URL = "jdbc:sqlite:chat.db"; // Ścieżka do bazy SQLite [cite: 64]
    public static final int MAX_CLIENTS = 10;
    private Constants() {
        // Prywatny konstruktor, aby zapobiec tworzeniu instancji
    }
}