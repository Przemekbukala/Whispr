package com.whispr.securechat.common;

/**
 * Defines all possible types of messages exchanged.
 */
public enum MessageType {
    // User login request message
    LOGIN,
    // User registration request message
    REGISTER,
    // User-to-user encrypted chat message
    CHAT_MESSAGE,
    // RSA public key exchange message for establishing secure sessions
    PUBLIC_KEY_EXCHANGE,
    // AES encrypted session key exchange message
    AES_KEY_EXCHANGE,
    // Server broadcast of currently online users
    USER_LIST_UPDATE,
    // Informational message from the server
    SERVER_INFO,
    // Error message indicating a problem
    ERROR,
    // User logout notification
    LOGOUT,
    // Administrator login request
    ADMIN_LOGIN,
    // Administrator request for user list update
    ADMIN_USER_LIST_UPDATE,
    // Server log message for administrator
    ADMIN_LOG_MESSAGE,
    // Administrator command to kick a user
    ADMIN_KICK_USER,
    // Administrator command to reset a user's password
    ADMIN_RESET_PASSWORD,
    // Notification to a user that they have been kicked by an administrator
    ADMIN_KICK_NOTIFICATION,
    // Notification that a secure session has been established
    SESSION_ESTABLISHED,
    // Response indicating successful login
    LOGIN_SUCCESS,
    // Response indicating failed login attempt
    LOGIN_FAILURE,
    // Response indicating successful registration
    REGISTER_SUCCESS,
    // Response indicating failed registration attempt
    REGISTER_FAILURE,
    // Request from a client for another user's public key (for E2E encryption)
    E2E_PUBLIC_KEY_REQUEST,
    // Response containing a requested user's public key
    E2E_PUBLIC_KEY_RESPONSE,
    // Message containing an encrypted E2E session key being shared between users
    E2E_SESSION_KEY_SHARE
}