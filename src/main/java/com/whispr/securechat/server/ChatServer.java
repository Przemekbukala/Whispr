package com.whispr.securechat.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.ExecutorService; // Do zarządzania pulą wątków
import java.util.concurrent.Executors;
// Importy dla exceptionów
import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.server.networking.ClientHandler;
import com.whispr.securechat.database.DatabaseManager;
import com.whispr.securechat.server.networking.ClientManager;

import static com.whispr.securechat.common.Constants.MAX_CLIENTS;
import static com.whispr.securechat.common.Constants.SERVER_PORT;

public class ChatServer {
    private final int port;
    private ServerSocket serverSocket;
    private ExecutorService clientThreadPool; // Pula wątków dla ClientHandlerów
    private DatabaseManager dbManager;
    private ClientManager clientManager; // Do zarządzania połączonymi klientami
    private boolean running;
    PrivateKey serverRSAPrivateKey;
    PublicKey serverRSAPublicKey;

    public ChatServer() {
        this.port = SERVER_PORT;
        this.clientThreadPool = Executors.newFixedThreadPool(MAX_CLIENTS);
        this.running = true;
        this.clientManager = new ClientManager();
        this.dbManager = new DatabaseManager();
        try {
            KeyPair keyPair = RSAEncryptionUtil.generateRSAKeyPair();
            assert keyPair != null;
            this.serverRSAPrivateKey = keyPair.getPrivate();
            this.serverRSAPublicKey = keyPair.getPublic();
            System.out.println("Server RSA keys generated.");
        } catch (Exception e) {
            System.err.println("Error generating server RSA keys: " + e.getMessage());
            // Możesz rzucić wyjątek, aby serwer nie wystartował bez kluczy
        }
    } // Konstruktor

    public void start() throws Exception {
        // Uruchamia ServerSocket i czeka na połączenia klientów [cite: 53]
        System.out.println("ChatServer is starting on port " + port + "...");
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("ChatServer successfully started on " +
                    InetAddress.getLocalHost() + ":" + port +
                    ". Waiting for connections...");

            while (running) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("New client connected: " +
                        clientSocket.getInetAddress().getHostAddress());
                ClientHandler clientHandler = new ClientHandler(clientSocket,this,serverRSAPrivateKey);
                clientManager.addClient(clientSocket.getInetAddress().getHostAddress(),clientHandler);
                clientThreadPool.execute(clientHandler);
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }


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
