package com.whispr.securechat.common;

/**
 * Contains application-wide constants used by both the client and server components.
 * <p>
 *  The class is final and cannot be instantiated, as it only provides static constants.
 */
public final class Constants {
    /** The default port number that the server listens on.*/
    public static final int SERVER_PORT = 8080;
    /** The AES algorithm specification used for symmetric encryption*/
    public static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    /** The RSA algorithm specification used for asymmetric encryption*/
    public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    /** The JDBC URL for the SQLite database connection */
    public static final String DB_URL = "jdbc:sqlite:src/main/java/com/whispr/securechat/database/chat.db";
    /** The maximum number of concurrent client connections the server will accept */
    public static final int MAX_CLIENTS = 10;
    /** 
     * The default administrator password for the application.
     * This should be removed  replaced with a secure solution!!
     */
    public static final String ADMIN_PASSWORD = "1234";
    /**
     * Private constructor to prevent instantiation of this utility class.
     * This class is meant to be used only for its static constants.
     */
    private Constants() {}
}