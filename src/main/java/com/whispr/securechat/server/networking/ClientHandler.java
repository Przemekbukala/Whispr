package com.whispr.securechat.server.networking;


import java.io.IOException;
import java.io.ObjectStreamException;
import java.net.Socket;
//import java.io.BufferedReader; // Jeśli używasz BufferedReader/PrintWriter
//import java.io.PrintWriter;    // Jeśli używasz BufferedReader/PrintWriter

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.security.PrivateKey;

import com.whispr.securechat.common.Message;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.database.DatabaseManager;
import com.whispr.securechat.server.ChatServer; // Może potrzebować dostępu do ClientManager

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private ChatServer server; // Referencja do serwera
    private ObjectInputStream objectIn;
    private ObjectOutputStream objectOut;

    private String username;
    private SecretKey aesKey; // Klucz AES dla tej sesji klienta
    private PrivateKey serverRSAPrivateKey; // Prywatny klucz RSA serwera

    // Konstruktor
    public ClientHandler(Socket socket, ChatServer server, PrivateKey serverRSAPrivateKey) throws IOException {
        this.clientSocket = socket;
        this.server = server;
        this.serverRSAPrivateKey = serverRSAPrivateKey;
        this.objectOut = new ObjectOutputStream(clientSocket.getOutputStream());
        this.objectIn = new ObjectInputStream(clientSocket.getInputStream());
    }

    @Override
    public void run() {
        // Główna pętla wątku, odczytująca i przetwarzająca wiadomości od klienta
        try {
            while (true) {
                try {
                    Message message = (Message) objectIn.readObject();
//                    System.out.println(message);
                    if (message != null) {
//                        handleMessage(message); // Przekieruj do obsługi wiadomości
                    System.out.println(message);
                    }

                    // TODO: Logika obsługi wiadomości (np. handleMessage(message))
                } catch (IOException e) {
                    System.out.println("Client " + clientSocket.getInetAddress().getHostAddress() + " disconnected or error reading: " + e.getMessage());
                    server.getClientManager().removeClient(clientSocket.getInetAddress().getHostAddress());
//                    server.getClientManager().removeClient(username);
                    break;
                } catch (ClassNotFoundException e) {
                    System.err.println("Received unknown object type from client " + clientSocket.getInetAddress().getHostAddress() + ": " + e.getMessage());
                    break;
                }
            }
        } finally {
            System.err.println("Closing connection for client: " + clientSocket.getInetAddress().getHostAddress());
            try{
                if (objectOut != null) objectOut.close();
                if (objectIn != null) objectIn.close();
            } catch (IOException e) {
                System.err.println("Error closing streams: " + e.getMessage());
            }
            try{
                if (clientSocket !=null) clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error closing client socket: " + e.getMessage());
            }
        }
    }

    public void sendMessage(Message message) throws Exception {
        // Wysyła wiadomość do tego klienta, szyfrując ją jeśli to wiadomość czatu
    }

    public String getUsername() { /* ... */
        return "";
    }

    public void setUsername(String username) { /* ... */ }

    public SecretKey getAesKey() { /* ... */
        return null;
    }

    public void setAesKey(SecretKey aesKey) { /* ... */ }

    private void handleMessage(Message message) throws Exception {
        // Przetwarza odebraną wiadomość w zależności od jej typu
    }

    private void performRsaKeyExchange(Message incomingMessage) throws Exception {
        // Obsługuje wymianę kluczy RSA (np. odebranie klucza publicznego klienta)
    }

    private void performAesKeyExchange(Message incomingMessage) throws Exception {
        // Obsługuje wymianę kluczy AES (zaszyfrowanych RSA)
    }

    private void authenticateUser(Message loginMessage) throws Exception {
        // Obsługuje logowanie/rejestrację
    }
}
