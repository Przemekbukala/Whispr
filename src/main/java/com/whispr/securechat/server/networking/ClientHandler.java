package com.whispr.securechat.server.networking;


import java.io.IOException;
import java.net.Socket;
//import java.io.BufferedReader; // Jeśli używasz BufferedReader/PrintWriter
//import java.io.PrintWriter;    // Jeśli używasz BufferedReader/PrintWriter
import com.google.gson.Gson;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Base64;

import com.whispr.securechat.common.Constants;
import com.whispr.securechat.common.LoginPayload;
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.MessageType;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.server.ChatServer; // Może potrzebować dostępu do ClientManager

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private ChatServer server; // Referencja do serwera
    private ObjectInputStream objectIn;
    private ObjectOutputStream objectOut;
    private static final Gson gson = new Gson();

    private String username;
    private SecretKey aesClientKey; // Klucz AES dla tej sesji klienta
    private PrivateKey serverRSAPrivateKey; // Prywatny klucz RSA serwera
    private boolean isAdmin = false;

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
                        //System.out.println(message); //TODO usunac to pozniej
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
        if (clientSocket.isClosed() || objectOut == null) {
            System.err.println("Attempted to send a message to a closed socket for user: " + username);
            return;
        }

        // "Inteligentne" szyfrowanie:
        // Jeśli klucz AES już istnieje (sesja jest bezpieczna), szyfrujemy payload.
        // Klucz AES jest naszym "strażnikiem" - jeśli ma wartość null, znaczy to, że
        // wymiana kluczy jeszcze się nie zakończyła.
        if (aesClientKey != null) {
            String plainTextPayload = message.getPayload();
            byte[] encryptedPayloadBytes = AESEncryptionUtil.encrypt(plainTextPayload.getBytes(), this.aesClientKey);
            String encryptedPayloadString = Base64.getEncoder().encodeToString(encryptedPayloadBytes);

            Message encryptedMessage = new Message(
                    message.getType(),
                    message.getSender(),
                    message.getRecipient(),
                    encryptedPayloadString,
                    message.getTimestamp()
            );

            objectOut.writeObject(encryptedMessage);
            objectOut.flush();

        } else {
            // Jeśli klucz AES nie istnieje, wysyłamy wiadomość bez szyfrowania
            // (dotyczy to np. początkowej wymiany kluczy RSA).
            objectOut.writeObject(message);
            objectOut.flush();
        }
    }

    public String getUsername() { /* ... */
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public SecretKey getAesClientKey() { /* ... */
        return aesClientKey;
    }

    public void setAesClientKey(SecretKey aesClientKey) {
        this.aesClientKey = aesClientKey;
    }

    void sendPublicKey(PublicKey publicKey) {
        try {
            PublicKey serverPublicKey = server.getServerRSAPublicKey();
            String encodedPublicKey = RSAEncryptionUtil.encodeToString(serverPublicKey.getEncoded());
            Message publicKeyMessage = new Message(
                    MessageType.PUBLIC_KEY_EXCHANGE,
                    "server",
                    "client",
                    encodedPublicKey,
                    System.currentTimeMillis()
            );
            sendMessage(publicKeyMessage);
            System.out.println("Serwer wysłał swój klucz publiczny RSA do " + clientSocket.getInetAddress().getHostAddress());
        } catch (Exception e) {
            System.err.println("Błąd wysyłania klucza publicznego serwera do klienta");
//            throw new RuntimeException(e);
        }
    }

    private void handleMessage(Message message) throws Exception {
        switch (message.getType()) {
            case PUBLIC_KEY_EXCHANGE:
                sendPublicKey(server.getServerRSAPublicKey());
                break;
            case LOGIN:
                handleLogin(message);
                break;
            case REGISTER:
                handleRegistration(message);
                break;
            case CHAT_MESSAGE:
                server.getClientManager().forwardMessage(message);
                break;
            case AES_KEY_EXCHANGE:
                handleAESKeyExchange(message);
                break;
            case ADMIN_LOGIN:
                handleAdminLogin(message);
                break;
            // ... inne przypadki
            default:
                // Co zrobić, gdy serwer otrzyma nieznany typ wiadomości?
                System.err.println("Received unknow message type: " + message.getType());
        }
    }

    private void handleAdminLogin(Message message) {
        try {
            String encodedPayload = message.getPayload();
            byte[] bPayload = Base64.getDecoder().decode(encodedPayload);
            byte[] decodedPayload = AESEncryptionUtil.decrypt(bPayload, this.aesClientKey);
            String decodedPassword = new String(decodedPayload, StandardCharsets.UTF_8);
            if (decodedPassword.equals(Constants.ADMIN_PASSWORD)) {
                this.isAdmin = true;
                server.getClientManager().addClient("admin_" + clientSocket.getRemoteSocketAddress(), this);
                System.out.println("DEBUG: Server is sending login SUCCESS message.");
                System.out.println("Admin authenticated successfully for client: " + clientSocket.getInetAddress());

                Message successMessage = new Message(
                        MessageType.SERVER_INFO,
                        "server",
                        "admin",
                        "Authentication successful. Welcome, admin.",
                        System.currentTimeMillis()
                );
                sendMessage(successMessage);
            } else {
                System.err.println("Failed admin login attempt from: " + clientSocket.getInetAddress());
                Message failureMessage = new Message(
                        MessageType.ERROR,
                        "server",
                        "admin",
                        "Authentication failed. Invalid password.",
                        System.currentTimeMillis()
                );
                sendMessage(failureMessage);
            }
        } catch (Exception e) {
            System.err.println("Error during admin login process: " + e.getMessage());
        }
    }

    private void handleAESKeyExchange(Message message) {
        try {
            String encodedPayload = message.getPayload();
            byte[] bPayload = Base64.getDecoder().decode(encodedPayload);
            byte[] decodedPayload = RSAEncryptionUtil.decrypt(bPayload, serverRSAPrivateKey);
            SecretKey clientKey = new SecretKeySpec(decodedPayload, "AES");
            setAesClientKey(clientKey);

            String recipient = message.getSender();

            Message aesConfirmationMessage = new Message(
                    MessageType.SERVER_INFO,
                    "server",
                    recipient,
                    "AES key received successfully. Session ready!",
                    System.currentTimeMillis()
            );
            sendMessage(aesConfirmationMessage);
        } catch (Exception e) {
            System.err.println("Failed to handle AES key exchange for " +
                    clientSocket.getInetAddress().getHostAddress() + ": " + e.getMessage());
        }
    }

    private void handleLogin(Message message) {
        String gsonPayload = message.getPayload();
        LoginPayload loginPayload = gson.fromJson(gsonPayload, LoginPayload.class);

        final String username = loginPayload.getUsername();
        final String password = loginPayload.getPassword();

        try {
            boolean wasLoginSuccessful = server.getDbManager().verifyCredentials(username, password);

            if (wasLoginSuccessful) {
                this.username = username;
                server.getClientManager().addClient(username, this);
                Message loginConfirmationMessage = new Message(MessageType.SERVER_INFO,
                        "server", username, "Logged successfully!",
                        System.currentTimeMillis());
                sendMessage(loginConfirmationMessage);
                server.getClientManager().broadcastUserList();
            } else {
                Message loginRejectionMessage = new Message(MessageType.ERROR,
                        "server", username, "Username or password incorrect!",
                        System.currentTimeMillis());
                sendMessage(loginRejectionMessage);
            }
        } catch (Exception e) {
            System.err.println("Error while logging in user: " + username);
            Message loginErrorMessage = new Message(MessageType.ERROR,
                    "server", username, "Server error during login.",
                    System.currentTimeMillis());
            try {
                sendMessage(loginErrorMessage);
            } catch (Exception ex) {
                System.err.println("Failed to send error message: " + ex.getMessage());
            }
            e.printStackTrace();
        }
    }

    private void handleRegistration(Message message) {
        String gsonPayload = message.getPayload();
        LoginPayload registrationPayload = gson.fromJson(gsonPayload, LoginPayload.class);

        final String username = registrationPayload.getUsername();
        final String password = registrationPayload.getPassword();

        try {
            boolean wasRegistrationSuccessful = server.getDbManager().registerUser(username, password);
            if (wasRegistrationSuccessful) {
                Message successfulRegistration = new Message(MessageType.SERVER_INFO,
                        "server", username, "Registration successful",
                        System.currentTimeMillis());
                sendMessage(successfulRegistration);
            } else {
                Message failureRegistration = new Message(MessageType.ERROR,
                        "server", username, "User with this name already exists.",
                        System.currentTimeMillis());
                sendMessage(failureRegistration);
            }
        } catch (Exception e) {
            System.err.println("Error during user registration: " + username);
            Message registrationErrorMessage = new Message(MessageType.ERROR,
                    "server", username, "Server error during registration.",
                    System.currentTimeMillis());
            try {
                sendMessage(registrationErrorMessage);
            } catch (Exception ex) {
                System.err.println("Failed to send error message: " + ex.getMessage());
            }
            e.printStackTrace();
        }
    }

    //TODO usnac na 99%
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
