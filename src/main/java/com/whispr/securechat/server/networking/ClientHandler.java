package com.whispr.securechat.server.networking;


import java.io.IOException;
import java.net.Socket;
//import java.io.BufferedReader; // Jeśli używasz BufferedReader/PrintWriter
//import java.io.PrintWriter;    // Jeśli używasz BufferedReader/PrintWriter
import com.google.gson.Gson;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Set;

import com.whispr.securechat.common.LoginPayload;
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.MessageType;
import com.whispr.securechat.common.User;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.server.ChatServer; // Może potrzebować dostępu do ClientManager

import static com.whispr.securechat.security.RSAEncryptionUtil.decryptRSA;
import static com.whispr.securechat.security.RSAEncryptionUtil.isBase64;
import static com.whispr.securechat.server.ChatServer.log;

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private ChatServer server; // Referencja do serwera
    private ObjectInputStream objectIn;
    private ObjectOutputStream objectOut;
    private static final Gson gson = new Gson();

    private String username;
    private SecretKey aesKey; // Klucz AES dla tej sesji klienta
    private PrivateKey serverRSAPrivateKey; // Prywatny klucz RSA serwera
    private PublicKey clientRSAPublicKey;
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
                        System.out.println(message);
                    }
                } catch (IOException e) {
                    // This block is now correct
                    String clientIdentifier = (username != null) ? username : "unauthenticated client";
                    System.err.println("Client " + clientIdentifier + " @ " + clientSocket.getInetAddress().getHostAddress() + " disconnected.");

                    if (username != null && !isAdmin) {
                        server.getClientManager().removeClient(username);
                    } else {
                        server.getClientManager().removeAdmin(username);
                    }
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


    //probably two layers of encrytpion
    // szyfruje i wysyła wiadomosc
//    public void sendMessage(Message message) throws Exception {
//        // Wysyła wiadomość do tego klienta, ktora nie jest zaszyfrowana więc szyfrujemy
//
//        if (!clientSocket.isClosed() && objectOut != null) {
//            if (message.getType() == MessageType.CHAT_MESSAGE) {
//                IvParameterSpec IV = AESEncryptionUtil.generateIVParameterSpec();
//                String contentToEncrypt = message.getPayload();
//                String encrypted_data = AESEncryptionUtil.encrypt(contentToEncrypt.getBytes(), this.aesKey, IV);
//                message.setPayload(encrypted_data);
//                message.setEncryptedIv(IV.getIV());
//                message.setTimestamp(System.currentTimeMillis());
//            }
//            objectOut.writeObject(message);
//            objectOut.flush();
//        } else {
//            System.err.println("Attempted to send a message to a closed socket for user: " + username);
//        }
//
//    }

    public void sendMessage(Message message) throws Exception {
        if (!clientSocket.isClosed() && objectOut != null) {
            objectOut.writeObject(message);
            objectOut.flush();
        } else {
            System.err.println("Attempted to send a message to a closed socket for user: " + username);
        }
    }

    public String getUsername() { /* ... */
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public SecretKey getAesKey() { /* ... */
        return aesKey;
    }

    public void setAesKey(SecretKey aesKey) {
        this.aesKey = aesKey;
    }


    void sendPublicRSAKey(PublicKey publicKey) {
        try {
            PublicKey serverPublicKey = server.getServerRSAPublicKey();
            String encodedPublicKey = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
            Message publicKeyMessage = new Message(
                    MessageType.PUBLIC_KEY_EXCHANGE,
                    "server",
                    username,
                    encodedPublicKey, null,
                    System.currentTimeMillis()
            );
            objectOut.writeObject(publicKeyMessage);
            objectOut.flush();
            System.out.println("The server sent its RSA public key to the " + clientSocket.getInetAddress().getHostAddress());
        } catch (IOException e) {
            System.err.println("Error sending server's public key to client");
        }
    }

    public String decryptChatMessage(Message message) throws Exception {
        if (this.aesKey == null) {
            throw new IllegalStateException("AES key not established for: " + username);
        }
        IvParameterSpec iv = new IvParameterSpec(message.getEncryptedIv());
        return AESEncryptionUtil.decrypt(message.getPayload(), this.aesKey, iv);
    }

    private void handleMessage(Message message) throws Exception {
        switch (message.getType()) {
            case PUBLIC_KEY_EXCHANGE:
                try {
                    String clientRSA = message.getPayload();
                    this.clientRSAPublicKey = RSAEncryptionUtil.decodePublicKey(clientRSA);
                    System.out.println("Received and saved the RSA public key from the client: ");
                } catch (Exception e) {
                    System.err.println("Error while decoding client's public key:" + e.getMessage());
                    throw e; // Rzuć wyjątek dalej, aby obsłużyć błąd w pętli run()
                }
                sendPublicRSAKey(server.getServerRSAPublicKey());
                break;
            case LOGIN:
                // Tutaj logika logowania
                handleLogin(message);
                break;
            case REGISTER:
                // Tutaj logika rejestracji
                handleRegistration(message);
                break;
            case CHAT_MESSAGE:
            case E2E_SESSION_KEY_SHARE:
                System.out.println("Forwarding an E2E messege from: " + message.getSender()
                        + " to " + message.getRecipient());
                server.getClientManager().forwardMessage(message);
                break;
//                processChatMessage(message);
            case E2E_PUBLIC_KEY_REQUEST:
                handlePublicKeyRequest(message);
                break;
            case ADMIN_LOGIN:
                handleAdminLogin(message);
                break;
            // ... inne przypadki
            case AES_KEY_EXCHANGE:
                try {
                    String encryptedAesKeyBase64 = message.getPayload();
                    System.out.println("Payload received on the server: " + message.getPayload());
                    if (!isBase64(encryptedAesKeyBase64)) {
                        throw new IllegalArgumentException("Invalid Base64 payload: " + encryptedAesKeyBase64);
                    }
                    byte[] encryptedAesKeyBytes = Base64.getDecoder().decode(encryptedAesKeyBase64);
                    byte[] decryptedAESKeyBytes = decryptRSA(encryptedAesKeyBytes, serverRSAPrivateKey);
                    // Sprawdzenie poprawność klucza AES
                    if (decryptedAESKeyBytes.length != 16 && decryptedAESKeyBytes.length != 24 && decryptedAESKeyBytes.length != 32) {
                        throw new IllegalArgumentException("Invalid AES length" + decryptedAESKeyBytes.length);
                    }

                    this.aesKey = new SecretKeySpec(decryptedAESKeyBytes, "AES");
                    System.out.println("The server received and decrypted the AES key from the client: " + username);

                    try {
                        IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                        String payloadToEncrypt = "AES key received successfully. Session ready!";
                        String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, iv);

                        Message sessionReadyMessage = new Message(MessageType.SERVER_INFO,
                                "server", username, encryptedData, iv.getIV(),
                                System.currentTimeMillis());
                        sendMessage(sessionReadyMessage);
                        System.out.println("Sent session ready confirmation to: " + username);
                    } catch (Exception e) {
                        System.err.println("Error sending session ready confirmation: " + e.getMessage());
                        e.printStackTrace();
                    }
                } catch (Exception e) {
                    System.err.println("Error while processing AES messages: " + e.getMessage());
                    e.printStackTrace();
                }
                break;
            // TU moze dodac waidomosc do klienta ze otryzmal to co chciał
            default:
                // Co zrobić, gdy serwer otrzyma nieznany typ wiadomości?
                System.err.println("Received unknow message type: " + message.getType());
        }
    }

    private void handlePublicKeyRequest(Message message) throws Exception {
        String recipientUsername = message.getPayload();
        String publicKey = server.getDbManager().getUserPublicKey(recipientUsername);

        Message response;
        IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();

        if (publicKey != null) {
            System.out.println("Found public key for: " + recipientUsername +
                    ", sending to: " + this.username);
            String jsonResponse = String.format("{\"username\":\"%s\",\"publicKey\":\"%s\"}", recipientUsername, publicKey);

            String encryptedPayload = AESEncryptionUtil.encrypt(jsonResponse.getBytes(), this.aesKey, iv);

            response = new Message(
                    MessageType.E2E_PUBLIC_KEY_RESPONSE,
                    "server",
                    this.username,
                    encryptedPayload,
                    iv.getIV(),
                    System.currentTimeMillis());

        } else {
            System.out.println("Could not find public key for " + recipientUsername);

            String encryptedError = AESEncryptionUtil.encrypt(("User not found: " + recipientUsername).getBytes(), this.aesKey, iv);

            response = new Message(
                    MessageType.ERROR,
                    "server",
                    this.username,
                    encryptedError,
                    iv.getIV(),
                    System.currentTimeMillis());
        }
        sendMessage(response);
    }

    private void handleLogin(Message message) {
        String username = null;
        try {
            String decryptedPayload = decryptChatMessage(message);
            LoginPayload loginPayload = gson.fromJson(decryptedPayload, LoginPayload.class);

            username = loginPayload.getUsername();
            final String password = loginPayload.getPassword();
            final String publicKey = loginPayload.getPublicKey(); // Extract the public key from the payload

            boolean wasLoginSuccessful = server.getDbManager().verifyCredentials(username, password);
            if (wasLoginSuccessful) {
                // If login is successful, update the user's public key in the database
                server.getDbManager().updateUserPublicKey(username, publicKey);

                this.username = username;
                server.getClientManager().addClient(username, this);

                IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                String payloadToEncrypt = "Logged successfully!";
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, iv);

                Message loginConfirmationMessage = new Message(MessageType.SERVER_INFO,
                        "server", username, encryptedData, iv.getIV(),
                        System.currentTimeMillis());
                sendMessage(loginConfirmationMessage);
                server.getClientManager().broadcastUserList();
            } else {
                IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                String payloadToEncrypt = "Username or password incorrect!";
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, iv);

                Message loginRejectionMessage = new Message(MessageType.ERROR,
                        "server", username, encryptedData, iv.getIV(),
                        System.currentTimeMillis());
                sendMessage(loginRejectionMessage);
            }
        } catch (Exception e) {
            // This catch block will now correctly handle errors
            System.err.println("Error during login process for user: " + username);
            e.printStackTrace();
            try {
                String payloadToEncrypt = "Server error during login.";
                IvParameterSpec errorIV = AESEncryptionUtil.generateIVParameterSpec();
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, errorIV);
                String recipient = (username != null) ? username : message.getSender();
                Message loginErrorMessage = new Message(MessageType.ERROR,
                        "server", recipient, encryptedData, errorIV.getIV(),
                        System.currentTimeMillis());
                sendMessage(loginErrorMessage);
            } catch (Exception ex) {
                System.err.println("Failed to send error message to client: " + ex.getMessage());
            }
        }
    }

    private void handleRegistration(Message message) {
        String username = null;
        try {
            String decryptedPayload = decryptChatMessage(message);
            LoginPayload registrationPayload = gson.fromJson(decryptedPayload, LoginPayload.class);

            username = registrationPayload.getUsername();
            final String password = registrationPayload.getPassword();
            final String publicKey = registrationPayload.getPublicKey();

            boolean wasRegistrationSuccessful = server.getDbManager().registerUser(username, password, publicKey);

            IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
            if (wasRegistrationSuccessful) {
                String payloadToEncrypt = "Registration successful";
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, iv);
                Message successfulRegistration = new Message(MessageType.SERVER_INFO,
                        "server", username, encryptedData, iv.getIV(),
                        System.currentTimeMillis());
                sendMessage(successfulRegistration);
            } else {
                String payloadToEncrypt = "User with this name already exists.";
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, iv);
                Message failureRegistration = new Message(MessageType.ERROR,
                        "server", username, encryptedData, iv.getIV(),
                        System.currentTimeMillis());
                sendMessage(failureRegistration);
            }
        } catch (Exception e) {
            System.err.println("Error during user registration process: " + e.getMessage());
            e.printStackTrace();
            try {
                String payloadToEncrypt = "Server error during registration.";
                IvParameterSpec errorIV = AESEncryptionUtil.generateIVParameterSpec();
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, errorIV);
                String recipient = (username != null) ? username : message.getSender();
                Message registrationErrorMessage = new Message(MessageType.ERROR,
                        "server", recipient, encryptedData, errorIV.getIV(),
                        System.currentTimeMillis());
                sendMessage(registrationErrorMessage);
            } catch (Exception ex) {
                System.err.println("Failed to send error message to client: " + ex.getMessage());
            }
        }
    }

    private void handleAdminLogin(Message message) {
        String adminUsername = null;
        try {
            String decryptedPayload = decryptChatMessage(message);
            LoginPayload loginPayload = gson.fromJson(decryptedPayload, LoginPayload.class);

            adminUsername = loginPayload.getUsername();
            final String password = loginPayload.getPassword();
            final String publicKey = loginPayload.getPublicKey(); // Extract the public key from the payload

            boolean wasLoginSuccessful = server.getDbManager().verifyAdminCredentials(adminUsername, password);
            if (wasLoginSuccessful) {
                // If login is successful, update the user's public key in the database
                log.info("Admin authentication successful for: {}", adminUsername);

                this.isAdmin = true;
                this.username = adminUsername;

                server.getDbManager().updateAdminPublicKey(adminUsername, publicKey);
                server.getClientManager().addAdmin(adminUsername, this);

                IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                String payloadToEncrypt = "Welcome admin!";
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, iv);

                Message loginConfirmationMessage = new Message(MessageType.SERVER_INFO,
                        "server", adminUsername, encryptedData, iv.getIV(),
                        System.currentTimeMillis());
                sendMessage(loginConfirmationMessage);

                Set<User> userList = server.getClientManager().getLoggedInUsers();
                String jsonPayload = new Gson().toJson(userList);
                IvParameterSpec iv2 = AESEncryptionUtil.generateIVParameterSpec();
                String encryptedPayload = AESEncryptionUtil.encrypt(jsonPayload.getBytes(), this.aesKey, iv2);
                Message userListMessage = new Message(
                        MessageType.ADMIN_USER_LIST_UPDATE,
                        "server",
                        adminUsername,
                        encryptedPayload,
                        iv2.getIV(),
                        System.currentTimeMillis()
                );
                sendMessage(userListMessage);

            } else {
                log.warn("Failed admin login attempt for username: {}", adminUsername);
                IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                String payloadToEncrypt = "Admin's username or password incorrect!";
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, iv);

                Message loginRejectionMessage = new Message(MessageType.ERROR,
                        "server", adminUsername, encryptedData, iv.getIV(),
                        System.currentTimeMillis());
                sendMessage(loginRejectionMessage);
            }
        } catch (Exception e) {
            // This catch block will now correctly handle errors
            log.error("Error during admin login process for: {}", adminUsername, e);
            System.err.println("Error during login process for admin: " + adminUsername);
            e.printStackTrace();
            try {
                String payloadToEncrypt = "Server error during admin's login.";
                IvParameterSpec errorIV = AESEncryptionUtil.generateIVParameterSpec();
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, errorIV);
                String recipient = (adminUsername != null) ? adminUsername : message.getSender();
                Message loginErrorMessage = new Message(MessageType.ERROR,
                        "server", recipient, encryptedData, errorIV.getIV(),
                        System.currentTimeMillis());
                sendMessage(loginErrorMessage);
            } catch (Exception ex) {
                System.err.println("Failed to send error message to admin client: " + ex.getMessage());
                log.error("Failed to send error message to admin client", ex);
            }
        }
    }
}