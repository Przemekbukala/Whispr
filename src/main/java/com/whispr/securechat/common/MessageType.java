package com.whispr.securechat.common;

public enum MessageType {
    LOGIN,
    REGISTER,
    CHAT_MESSAGE,
    PUBLIC_KEY_EXCHANGE, // Wymiana klucza publicznego RSA
    AES_KEY_EXCHANGE,    // Wymiana zaszyfrowanego klucza AES
    USER_LIST_REQUEST,
    USER_LIST_UPDATE,
    SERVER_INFO,
    ERROR,
    LOGOUT
}