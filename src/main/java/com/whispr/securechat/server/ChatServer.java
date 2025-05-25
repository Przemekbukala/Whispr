package com.whispr.securechat.server;

import java.net.ServerSocket;
import java.util.concurrent.ExecutorService; // Do zarządzania pulą wątków
// Importy dla exceptionów
import com.whispr.securechat.server.networking.ClientHandler;
import com.whispr.securechat.database.DatabaseManager;
import com.whispr.securechat.server.networking.ClientManager;

public class ChatServer {
    private int port;
    private ServerSocket serverSocket;
    private ExecutorService clientThreadPool; // Pula wątków dla ClientHandlerów
    private DatabaseManager dbManager;
    private ClientManager clientManager; // Do zarządzania połączonymi klientami

    public ChatServer(int port) { /* ... */ } // Konstruktor

    public void start() throws Exception {
        // Uruchamia ServerSocket i czeka na połączenia klientów [cite: 53]
    }

    public void stop() {
        // Zatrzymuje serwer i zamyka wszystkie połączenia
    }

    // Metody pomocnicze (np. do obsługi logiki serwera przekazywanej z ClientHandler)
    public ClientManager getClientManager() { /* ... */
        return null;
    }
    public DatabaseManager getDbManager() { /* ... */
        return null;
    }
}
