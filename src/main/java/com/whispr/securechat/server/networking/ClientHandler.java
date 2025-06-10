package com.whispr.securechat.server.networking;


import java.io.IOException;
import java.io.ObjectStreamException;
import java.net.Socket;
//import java.io.BufferedReader; // Jeśli używasz BufferedReader/PrintWriter
//import java.io.PrintWriter;    // Jeśli używasz BufferedReader/PrintWriter
import com.google.gson.Gson;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Base64;

import com.whispr.securechat.common.LoginPayload;
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.MessageType;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.database.DatabaseManager;
import com.whispr.securechat.server.ChatServer; // Może potrzebować dostępu do ClientManager

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private ChatServer server; // Referencja do serwera
    private ObjectInputStream objectIn;
    private ObjectOutputStream objectOut;
    private static final Gson gson = new Gson();

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
                        try {
                            handleMessage(message); // Przekieruj do obsługi wiadomości
                        } catch (Exception e) {
                            System.err.println("Error handling message!");
                            break;
                        }
                        System.out.println(message);
                    }
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
            try {
                if (objectOut != null) objectOut.close();
                if (objectIn != null) objectIn.close();
            } catch (IOException e) {
                System.err.println("Error closing streams: " + e.getMessage());
            }
            try {
                if (clientSocket != null) clientSocket.close();
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

    void sendPublicKey(PublicKey publicKey) {
        try {
            PublicKey serverPublicKey = server.GetserverRSAPublicKey();
            String encodedPublicKey = RSAEncryptionUtil.encodeToString(serverPublicKey.getEncoded());
            Message publicKeyMessage = new Message(
                    MessageType.PUBLIC_KEY_EXCHANGE,
                    "server",
                    "client",
                    encodedPublicKey,
                    System.currentTimeMillis()
            );
            objectOut.writeObject(publicKeyMessage);
            objectOut.flush();
            System.out.println("Serwer wysłał swój klucz publiczny RSA do " + clientSocket.getInetAddress().getHostAddress());
        } catch (IOException e) {
            System.err.println("Błąd wysyłania klucza publicznego serwera do klienta");
        }
    }



    private void handleMessage(Message message) throws Exception {
        switch (message.getType()) {
            case PUBLIC_KEY_EXCHANGE:
                sendPublicKey(server.GetserverRSAPublicKey());
                break;
            case LOGIN:
                // Tutaj logika logowania
                handleLogin(message);
                break;
            case REGISTER:
                // Tutaj logika rejestracji
                break;
            case CHAT_MESSAGE:
                // Tutaj logika przesyłania wiadomości
                break;
            // ... inne przypadki
            default:
                // Co zrobić, gdy serwer otrzyma nieznany typ wiadomości?
                System.out.println("Otrzymano nieznany typ wiadomości: " + message.getType());
        }
    }

    private void handleLogin(Message message) {
        String gsonPayload = message.getPayload();
        LoginPayload loginPayload = gson.fromJson(gsonPayload, LoginPayload.class);

        String username = loginPayload.getUsername();
        String password = loginPayload.getPassword();

        try {
            boolean ifLogInSucccessful = server.getDbManager().verifyCredentials(username, password);

            if (ifLogInSucccessful){
                this.username = username;
                server.getClientManager().addClient(username,this);
                Message loginConfirmationMessage = new Message(MessageType.SERVER_INFO,
                        "server",username,"Logged successfully!",
                        System.currentTimeMillis());
                sendMessage(loginConfirmationMessage);
                server.getClientManager().broadcastUserList();
            } else {
                Message loginRejectionMessage = new Message(MessageType.ERROR,
                        "server",username,"Username or password incorrect!",
                        System.currentTimeMillis());
                sendMessage(loginRejectionMessage);
            }
        } catch (Exception e) {
            System.err.println("Error during logging user: " + username);
            Message loginErrorMessage = new Message(MessageType.ERROR,
                    "server",username,"Error during logging!",
                    System.currentTimeMillis());
            try{
            sendMessage(loginErrorMessage);} catch (Exception ex) {
                System.err.println("Error!");
            }
            e.printStackTrace();
        }
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
