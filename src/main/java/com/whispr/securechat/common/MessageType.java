package com.whispr.securechat.common;

public enum MessageType {
    LOGIN,
    REGISTER,
    CHAT_MESSAGE,
    PUBLIC_KEY_EXCHANGE, // Wymiana klucza publicznego RSA
    AES_KEY_EXCHANGE,    // Wymiana zaszyfrowanego klucza AES
    USER_LIST_UPDATE,
    SERVER_INFO,
    ERROR,
    LOGOUT,

    ADMIN_LOGIN,
    ADMIN_USER_LIST_UPDATE,
    ADMIN_LOG_MESSAGE,
    ADMIN_KICK_USER,
    ADMIN_RESET_PASSWORD,
    ADMIN_KICK_NOTIFICATION,

    SESSION_ESTABLISHED,
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    REGISTER_SUCCESS,
    REGISTER_FAILURE,

    E2E_PUBLIC_KEY_REQUEST,  // Client requests another user's public key
    E2E_PUBLIC_KEY_RESPONSE, // Server responds with the requested public key
    E2E_SESSION_KEY_SHARE    // Client A shares the E2E AES key with Client B
}