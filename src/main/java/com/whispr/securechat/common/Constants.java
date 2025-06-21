package com.whispr.securechat.common;

public final class Constants {
    public static final int SERVER_PORT = 8080; // Przykładowy port
    public static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final String HASH_ALGORITHM = "BCrypt";
    public static final String DB_URL = "jdbc:sqlite:src/main/java/com/whispr/securechat/database/chat.db";
    public static final int MAX_CLIENTS = 10;
    public static final String ADMIN_PASSWORD = "1234";

    private Constants() {
    }
}