package com.whispr.securechat.server;

import com.whispr.securechat.database.DatabaseManager;
import com.whispr.securechat.server.networking.ClientManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ChatServerTest {

    private ChatServer chatServer;

    @BeforeEach
    void setUp() {
        System.setProperty("DB_URL", "jdbc:sqlite:src/test/java/com/whispr/securechat/database/test_chat.db");
        chatServer = new ChatServer();
    }

    @Test
    void testServerInitialization() {
        assertNotNull(chatServer, "ChatServer instance should not be null.");
        assertNotNull(chatServer.getClientManager(), "ClientManager should be initialized.");
        assertNotNull(chatServer.getDbManager(), "DatabaseManager should be initialized.");
        assertNotNull(chatServer.getServerRSAPublicKey(), "Server RSA public key should be generated.");
        assertNotNull(chatServer.serverRSAPrivateKey, "Server RSA private key should be generated.");
        assertTrue(chatServer.isRunning(), "Server should be in a running state initially.");
    }

    @Test
    void testGetClientManager() {
        ClientManager clientManager = chatServer.getClientManager();
        assertNotNull(clientManager, "getClientManager should return a non-null instance.");
    }

    @Test
    void testGetDbManager() {
        DatabaseManager dbManager = chatServer.getDbManager();
        assertNotNull(dbManager, "getDbManager should return a non-null instance.");
    }

    @Test
    void testGetServerRSAPublicKey() {
        assertNotNull(chatServer.getServerRSAPublicKey(), "getServerRSAPublicKey should return a valid public key.");
    }

    @Test
    void testIsRunning() {
        assertTrue(chatServer.isRunning(), "isRunning should be true after initialization.");
    }
}