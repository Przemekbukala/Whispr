package com.whispr.securechat.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.server.networking.ClientHandler;
import com.whispr.securechat.database.DatabaseManager;
import com.whispr.securechat.server.networking.ClientManager;
import static com.whispr.securechat.common.Constants.MAX_CLIENTS;
import static com.whispr.securechat.common.Constants.SERVER_PORT;


/**
 * The main class for the Whispr Secure Chat Server.
 * It initializes the server, manages client connections using a thread pool,
 * and holds server-wide resources like cryptographic keys and the database manager.
 */
public class ChatServer {
    private final int port;
    private ServerSocket serverSocket;
    private ExecutorService clientThreadPool; // Pula wątków dla ClientHandlerów
    private DatabaseManager dbManager;
    private ClientManager clientManager; // Do zarządzania połączonymi klientami
    public static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ChatServer.class);
    private static ChatServer instance;

    private boolean running;
    PrivateKey serverRSAPrivateKey;
    PublicKey serverRSAPublicKey;


    /**
     * Constructs a new ChatServer instance.
     * Initializes the thread pool, client manager, database manager, and generates
     * the server's RSA key pair for secure communication.
     */
    public ChatServer() {
        this.port = SERVER_PORT;
        this.clientThreadPool = Executors.newFixedThreadPool(MAX_CLIENTS);
        this.running = true;
        this.clientManager = new ClientManager();
        this.dbManager = new DatabaseManager();
        this.dbManager.initializeDatabase();
        instance = this;

        try {
            KeyPair keyPair = RSAEncryptionUtil.generateRSAKeyPair();
            assert keyPair != null;
            this.serverRSAPrivateKey = keyPair.getPrivate();
            this.serverRSAPublicKey = keyPair.getPublic();
            System.out.println("Server RSA keys generated.");
        } catch (Exception ex) {
            System.err.println("Error generating server RSA keys: " + ex.getMessage());
        }
    }


    /**
     * Starts the server, binds it to the specified port, and begins listening for client connections.
     * Each new connection is offloaded to a {@link ClientHandler} in the thread pool.
     * @throws RuntimeException if the server cannot be started.
     */
    public void start() throws Exception {
        // Uruchamia ServerSocket i czeka na połączenia klientów
        log.info("ChatServer is starting on port {}...", port);
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("ChatServer successfully started on " +
                    InetAddress.getLocalHost() + ":" + port +
                    ". Waiting for connections...");
            while (isRunning()) {
                Socket clientSocket = null;
                ClientHandler clientHandler;
                try {
                    clientSocket = serverSocket.accept();
                    System.out.println("New client connected: " + clientSocket.getInetAddress().getHostAddress());
                    // dodałem sprawdzenie czy clienthendler nie rzuca wyjątku IOException.
                    try {
                        clientHandler = new ClientHandler(clientSocket, this, serverRSAPrivateKey);
                    } catch (IOException e) {
                        System.err.println("Failed to create ClientHandler: " + e.getMessage());
                        clientSocket.close();
                        continue;
                    }
                    clientThreadPool.execute(clientHandler);
                } catch (IOException e) {
                    System.err.println("Error accepting or handling client connection: " + e.getMessage());
                    if (clientSocket != null && running) {
                        try {
                            clientSocket.close();
                            System.out.println("Closed faulty client socket.");
                        } catch (IOException ex) {
                            System.err.println("Error closing faulty client socket: " + ex.getMessage());
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Server critical error: " + e.getMessage());
        }
    }

    /**
     * Stops the server gracefully.
     * It closes the server socket, shuts down the client thread pool, and disconnects all clients.
     */
    //TODO czy to powinno byc gdzies wywolywane
    public void stop() {
        running = false;
        try {
            if (serverSocket != null) serverSocket.close();
            clientThreadPool.shutdown();
            clientManager.getLoggedInUsers().forEach(user -> clientManager.removeClient(user.getUsername()));
        } catch (IOException e) {
            System.err.println("Error stopping server: " + e.getMessage());
        }
    }

    /**
     * Returns the manager responsible for all connected clients.
     * @return The singleton {@link ClientManager} instance.
     */
    public ClientManager getClientManager() { /* ... */
        return this.clientManager;
    }

    /**
     * Returns the server's public RSA key.
     * This key is sent to clients to allow them to securely send the AES session key.
     * @return The server's {@link PublicKey}.
     */
    public PublicKey getServerRSAPublicKey() {
        return serverRSAPublicKey;
    }

    /**
     * Returns the manager for database operations.
     * @return The singleton {@link DatabaseManager} instance.
     */
    public DatabaseManager getDbManager() { /* ... */
        return this.dbManager;
    }

    /**
     * Checks if the server is currently running.
     * @return true if the server is running, false otherwise.
     */
    public boolean isRunning() {
        return running;
    }

    /**
     * The main entry point for the server application.
     * @param args Command line arguments (not used).
     */
    public static void main(String[] args) throws Exception {
        ChatServer obj = new ChatServer();
        obj.start();
    }
}
