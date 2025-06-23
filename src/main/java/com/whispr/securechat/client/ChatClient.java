package com.whispr.securechat.client;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
// Importy dla exceptionów
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.whispr.securechat.client.networking.ClientNetworkManager;
import com.whispr.securechat.common.*;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.whispr.securechat.common.MessageType.*;
import static com.whispr.securechat.security.RSAEncryptionUtil.*;

/**
 * The core logic class for the client-side of the Whispr application.
 * This class manages the network connection, cryptographic keys, user session,
 * and the logic for sending and receiving messages. It interacts with the GUI controllers
 * to provide updates and handle user actions.
 */
public class ChatClient implements ClientNetworkManager.ConnectionStatusNotifier {
    private final String serverAddress;
    private final int serverPort;
    private ClientNetworkManager networkManager;
    private String username;
    private final SecretKey aesKey; // Client-Server session key
    private final KeyPair rsaKeyPair; // Client's own RSA key pair
    private PublicKey serverRSAPublicKey; // Server's public key for establishing the secure session
    private MessageReceivedListener messageListener;
    private UserListListener userListListener;
    private ConnectionStatusListener connectionStatusListener;
    private boolean clientPublicKeySent = false;
    private boolean clientAESKeySent = false;
    private final ConcurrentHashMap<String, SecretKey> conversationKeys; // E2E encryption keys: maps a recipient's username to the shared AES key
    private final ConcurrentHashMap<String, PublicKey> userPublicKeys; // Caches the public keys of other users for starting E2E sessions
    private final Gson gson = new Gson();
    private final Map<String, Queue<String>> pendingMessages;
    private ErrorListener errorListener;
    private SessionStateListener sessionListener;
    private AuthListener authListener;
    private KickedListener kickedListener;
    private Set<User> bufferedUserList = null;
    private static final Logger clientLog = LoggerFactory.getLogger(ChatClient.class);

    /**
     * Constructs a new ChatClient.
     * @param serverAddress The IP address or hostname of the chat server.
     * @param serverPort The port number of the chat server.
     */
    public ChatClient(String serverAddress, int serverPort) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.networkManager = null;
        this.conversationKeys = new ConcurrentHashMap<>();
        this.userPublicKeys = new ConcurrentHashMap<>();
        this.pendingMessages = new ConcurrentHashMap<>();
        setConnectionStatusListener(connected -> {
            if (connected) {
                clientLog.info("Connection to server established.");
            } else {
                clientLog.warn("Disconnected from server.");
            }
        });
        try {
            this.rsaKeyPair = RSAEncryptionUtil.generateRSAKeyPair();
            this.aesKey = AESEncryptionUtil.generateAESKey();
        } catch (Exception e) {
            // REVIEW: Throwing a RuntimeException here is acceptable for a critical startup failure.
            // Logging it provides more context.
            clientLog.error("FATAL: Could not generate cryptographic keys.", e);
            throw new RuntimeException(e);
        }
    }

//    public static void main(String[] args) {
//        ChatClient client = new ChatClient("localhost", Constants.SERVER_PORT);
//        try {
//            client.connect();
//            client.sendClientPublicRSAKey();
//            Thread.sleep(500); // Give time for key exchange
//            client.sendClientAESKey();
//            System.out.println("Secure session with server established.");
//            Thread.sleep(500);
//
//            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
//            while (true) {
//                System.out.println("Enter 'register' or 'login':");
//                String action = reader.readLine();
//
//                if ("register".equalsIgnoreCase(action)) {
//                    System.out.println("Enter username:");
//                    String username = reader.readLine();
//                    System.out.println("Enter password:");
//                    String password = reader.readLine();
//                    client.register(username, password);
//                    // In a real app, you'd wait for a success message.
//                    // For this test, we'll just try to log in next.
//                    System.out.println("Registration request sent. Please restart and log in.");
//                    return;
//                } else if ("login".equalsIgnoreCase(action)) {
//                    System.out.println("Enter username:");
//                    String username = reader.readLine();
//                    System.out.println("Enter password:");
//                    String password = reader.readLine();
//                    client.login(username, password);
//                    break;
//                } else {
//                    System.out.println("Invalid action. Use 'register' or 'login'.");
//                }
//            }
//
//            System.out.println("\nEnter messages in the format 'recipient:message'. Type 'exit' to quit.");
//            while (true) {
//                String line = reader.readLine();
//                if (line == null || "exit".equalsIgnoreCase(line)) {
//                    client.disconnect();
//                    break;
//                }
//
//                String[] parts = line.split(":", 2);
//                if (parts.length == 2) {
//                    String recipient = parts[0].trim();
//                    String messageText = parts[1].trim();
//                    client.sendMessage(recipient, messageText);
//                } else {
//                    System.out.println("Invalid format. Use 'recipient:message'.");
//                }
//            }
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }

    /**
     * Connects the client to the server.
     * Initializes the {@link ClientNetworkManager} and starts its listening thread.
     * @throws Exception if the connection fails.
     */
    public void connect() throws Exception {
        this.networkManager = new ClientNetworkManager(new Socket(serverAddress, serverPort));
        this.networkManager.setMessageReceiver(this::handleIncomingMessage);
        new Thread(networkManager).start(); //   pętlę run()  w ClientNetworkManager
        System.out.println("Połączono z serwerem: " + serverAddress + ":" + serverPort);
        this.networkManager.setConnectionStatusNotifier(this);
        // setting onConnectionStatusChanged
        if (connectionStatusListener != null) {
            connectionStatusListener.onConnectionStatusChanged(true);
        } else {
            throw new RuntimeException("ConnectionStatusListener not set.");
        }
    }

    /**
     * Sends a chat message to a specific recipient.
     * If an E2E session is not yet established with the recipient, it initiates one first
     * and queues the message to be sent upon successful key exchange.
     * Otherwise, it encrypts the message with the established E2E AES key and sends it.
     *
     * @param recipient The username of the message recipient.
     * @param messageToSend The plaintext message content.
     * @throws Exception if sending the message fails.
     */
    public void sendMessage(String recipient, String messageToSend) throws Exception {
        if (!conversationKeys.containsKey(recipient)) {
            clientLog.info("No secure E2E session with '{}'. Initiating key exchange.", recipient);
            //TODO disable send button until the exchange is complete
            System.out.println("No secure session with " + recipient + ". Initiating...");
            pendingMessages.computeIfAbsent(recipient, k -> new LinkedList<>()).add(messageToSend);
            initiateSecureSession(recipient);
            return;
        }

        SecretKey e2eAESKey = conversationKeys.get(recipient);
        IvParameterSpec IV = AESEncryptionUtil.generateIVParameterSpec();
        String encryptedData = AESEncryptionUtil.encrypt(messageToSend.getBytes(), e2eAESKey, IV);

        Message message = new Message(
                CHAT_MESSAGE,
                username,
                recipient,
                encryptedData,
                IV.getIV(),
                System.currentTimeMillis()
        );

        networkManager.sendData(message);
        System.out.println("Sent E2E encrypted message to: " + recipient);
        clientLog.info("Sent E2E encrypted message to: {}", recipient);
    }

    /**
     * Initiates a secure E2E session with another user.
     * It sends a request to the server for the recipient's public RSA key.
     * @param recipient The username of the user to establish a session with.
     * @throws Exception if the request fails.
     */
    public void initiateSecureSession(String recipient) throws Exception {
        Message publicKeyRequest = new Message(
                E2E_PUBLIC_KEY_REQUEST,
                this.username,
                "server",
                recipient, // payload is the username we want the key for
                System.currentTimeMillis()
        );
        networkManager.sendData(publicKeyRequest);
    }

    /**
     * Disconnects the client from the server and cleans up resources.
     */
    public void disconnect() {
        if (networkManager != null) {
            networkManager.close();
            networkManager = null;
        }
        System.out.println("Disconnected from the server.");
        if (connectionStatusListener != null) {
            connectionStatusListener.onConnectionStatusChanged(false);
        }
        System.out.println("User " + this.username + " disconnected from the server.");

    }

    /**
     * Sends the client's public RSA key to the server.
     * This is the first step in establishing the secure client-server session.
     * @throws Exception if sending the key fails.
     */
    public synchronized void sendClientPublicRSAKey() throws Exception {
        if (rsaKeyPair == null || rsaKeyPair.getPublic() == null) {
            System.err.println("Client public key could not be found.");
            return;
        }
        if (clientPublicKeySent) {
            System.out.println("Client public key already sent");
            return;
        }

        Message message = new Message(
                PUBLIC_KEY_EXCHANGE,
                username,
                "server",
                Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()),
                System.currentTimeMillis()
        );
        networkManager.sendData(message);
        clientPublicKeySent = true;
        System.out.println("The client's RSA public key was sent.");

    }

    /**
     * Generates an AES session key, encrypts it with the server's public RSA key,
     * and sends it to the server. This completes the client-server session setup.
     * @throws Exception if the server's public key is not available or sending fails.
     */
    public synchronized void sendClientAESKey() throws Exception {
        if (aesKey == null) {
            System.err.println("AES key is empty");
            return;
        }
        if (serverRSAPublicKey == null) {
            System.err.println("Server's RSA public key not established.");
            if (sessionListener != null) sessionListener.onSessionFailed("Server public key is missing.");
            return;
        }
        if (clientAESKeySent) {
            System.out.println("AES key was already sent");
            return;
        }
        byte[] aesKeyBytes = aesKey.getEncoded();
        System.out.println("Generated AES Key (Base64): " + Base64.getEncoder().encodeToString(aesKeyBytes));
        byte[] encryptedAesKey = encryptRSA(aesKeyBytes, serverRSAPublicKey);
        String encryptedAesKeyBase64 = Base64.getEncoder().encodeToString(encryptedAesKey);
        Message aesKeyMessage = new Message(
                MessageType.AES_KEY_EXCHANGE,
                username,
                "server",
                encryptedAesKeyBase64,
                System.currentTimeMillis()
        );
        // Senbding message
        networkManager.sendData(aesKeyMessage);
        System.out.println("An encrypted AES key was sent.");
        clientAESKeySent = true;
    }

    // Wewnętrzna klasa/interfejs do obsługi odbierania wiadomości od serwera troche to hjest myslace
    private void handleIncomingMessage(Message message) {
        switch (message.getType()) {
            case PUBLIC_KEY_EXCHANGE:
                try {
                    String publicKeyEncoded = message.getPayload();
                    this.serverRSAPublicKey = RSAEncryptionUtil.decodePublicKey(publicKeyEncoded);
                    System.out.println("The server's RSA key has been received.");
                    sendClientAESKey();
                } catch (Exception e) {
                    // ... obsługa błędu
                    if (sessionListener != null) {
                        sessionListener.onSessionFailed("Could not process server public key.");
                    }
                }
                break;

            case E2E_PUBLIC_KEY_RESPONSE:
                try {
                    String decryptedPayload = decryptedPayload(message);

                    if (decryptedPayload == null) {
                        throw new Exception("Failed to decrypt payload for E2E_PUBLIC_KEY_RESPONSE");
                    }

                    JsonObject json = gson.fromJson(decryptedPayload, JsonObject.class);
                    String targetUser = json.get("username").getAsString();
                    String publicKeyString = json.get("publicKey").getAsString();

                    PublicKey userKey = RSAEncryptionUtil.decodePublicKey(publicKeyString);
                    userPublicKeys.put(targetUser, userKey);

                    //weve public key - we need aes key
                    SecretKey sharedAESKey = AESEncryptionUtil.generateAESKey();
                    assert sharedAESKey != null;
                    conversationKeys.put(targetUser, sharedAESKey);

                    byte[] encryptedAESKey = RSAEncryptionUtil.encryptRSA(sharedAESKey.getEncoded(), userKey);
                    String encryptedAESKeyBase64 = Base64.getEncoder().encodeToString(encryptedAESKey);

                    Message keyShareMessage = new Message(
                            E2E_SESSION_KEY_SHARE,
                            this.username,
                            targetUser,
                            encryptedAESKeyBase64,
                            System.currentTimeMillis()
                    );

                    networkManager.sendData(keyShareMessage);
                    System.out.println("Shared E2E session key with: " + targetUser);

                    Queue<String> pending = pendingMessages.get(targetUser);
                    while (pending != null && !pending.isEmpty()) {
                        sendMessage(targetUser, pending.poll());
                    }

                } catch (Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace();
                }
                break;

            case E2E_SESSION_KEY_SHARE:
                try {
                    //now we receiving shared key
                    String sender = message.getSender();
                    byte[] encryptedAESKey = Base64.getDecoder().decode(message.getPayload());

                    byte[] decryptedAESKeyBytes = RSAEncryptionUtil.decryptRSA(encryptedAESKey, this.rsaKeyPair.getPrivate());
                    SecretKey sharedKey = new SecretKeySpec(decryptedAESKeyBytes, 0, decryptedAESKeyBytes.length, "AES");

                    //store it
                    conversationKeys.put(sender, sharedKey);
                    System.out.println("Established secure E2E session with " + sender);
                    Queue<String> pending = pendingMessages.get(sender);
                    while (pending != null && !pending.isEmpty()) {
                        sendMessage(sender, pending.poll());
                    }
                } catch (Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace();
                }
                break;

            case CHAT_MESSAGE:
                //decrypt with specific key
                SecretKey conversationKey = conversationKeys.get(message.getSender());
                if (conversationKey != null) {
                    try {
                        IvParameterSpec iv = new IvParameterSpec(message.getEncryptedIv());
                        String content = AESEncryptionUtil.decrypt(message.getPayload(), conversationKey, iv);
                        System.out.println("Decrypted E2E message from " + message.getSender() + ": " + content);

                        //notify message listener
                        if (messageListener != null) {
                            messageListener.onMessageReceived(message.getSender(), content);
                        }
                    } catch (Exception e) {
                        System.err.println("Failed to decrypt E2E message.");
                        e.printStackTrace();
                    }
                } else {
                    System.err.println("Received chat message from " + message.getSender() +
                            " but no E2E session is established.");
                }
                break;
            case AES_KEY_EXCHANGE:
                try {
                    sendClientAESKey();
                } catch (Exception e) {
                    System.err.println("Error when sending AES Key");
                    e.printStackTrace();
                }
                break;
            case USER_LIST_UPDATE:
                try {
                    String jsonPayload = decryptedPayload(message);
                    if (jsonPayload == null || jsonPayload.isBlank()) {
                        System.err.println("Failed to decrypt user list update.");
                        break;
                    }

                    System.out.println("ChatClient: Received USER_LIST_UPDATE, payload: " + jsonPayload);

                    java.lang.reflect.Type userSetType = new com.google.gson.reflect.TypeToken<java.util.Set<User>>() {
                    }.getType();
                    java.util.Set<User> users = gson.fromJson(jsonPayload, userSetType);
                    users.removeIf(user -> user.getUsername().equals(this.username));

                    if (this.userListListener != null) {
                        System.out.println("Listener is ready. Updating user list in GUI.");
                        this.userListListener.onUserListUpdated(users);
                    } else {
                        System.out.println("Listener not ready. Buffering user list.");
                        this.bufferedUserList = users;
                    }
                } catch (Exception e) {
                    System.err.println("Error processing user list update: " + e.getMessage());
                    e.printStackTrace();
                }
                break;

            case SERVER_INFO:
                String serverMessage = decryptedPayload(message);
                if (serverMessage != null && serverMessage.startsWith("AES key received successfully")) {
                    if (sessionListener != null) {
                        sessionListener.onSessionEstablished();
                    }
                }
                // obsłuż inne komunikaty SERVER_INFO, jeśli są
                break;

            case LOGIN_SUCCESS:
                if (authListener != null) authListener.onLoginSuccess();
                break;
            case LOGIN_FAILURE:
                if (authListener != null) authListener.onLoginFailure(decryptedPayload(message));
                break;
            case REGISTER_SUCCESS:
                if (authListener != null) authListener.onRegisterSuccess();
                break;
            case REGISTER_FAILURE:
                if (authListener != null) authListener.onRegisterFailure(decryptedPayload(message));
                break;
            case ADMIN_KICK_NOTIFICATION:
                String reason = decryptedPayload(message);
                if (kickedListener != null) {
                    kickedListener.onKicked(reason);
                }
                disconnect();
                break;
            case ERROR: // Istniejący case ERROR nadal może być używany
                String errorMessage = decryptedPayload(message);
                System.err.println("ERROR from server: " + errorMessage);
                // Możemy zmapować ogólne błędy na konkretne niepowodzenia
                if (authListener != null) {
                    if (errorMessage.contains("incorrect")) {
                        authListener.onLoginFailure(errorMessage);
                    } else if (errorMessage.contains("exists")) {
                        authListener.onRegisterFailure(errorMessage);
                    }
                }
                break;
            default:
                System.out.println("A message of an unsupported type was received: " + message.getType());
        }

    }

    public String decryptedPayload(Message message) {
        if (this.aesKey == null) {
            System.err.println("Brak klucza AES sesji");
            return null;
        }
        byte[] ivBytes = message.getEncryptedIv();
        if (ivBytes == null) {
            System.err.println("Brak wektora IV w wiadomości.");
            return null;
        }
        IvParameterSpec IV = new IvParameterSpec(ivBytes);
        String decryptedPayload = null;
        try {
            decryptedPayload = AESEncryptionUtil.decrypt(message.getPayload(), this.aesKey, IV);
        } catch (Exception e) {
            System.err.println("Błąd podczas deszyfrowania wiadomości AES: " + e.getMessage());
            throw new RuntimeException(e);
        }
        return decryptedPayload;
    }

    /**
     * A listener for incoming chat messages.
     */
    public interface MessageReceivedListener {
        void onMessageReceived(String sender, String content);
    }

    /**
     * Logs the user in.
     * Encrypts login credentials with the client-server session key and sends them.
     * @param username The username.
     * @param password The password.
     * @throws Exception if the login request fails.
     */
    public void login(String username, String password) throws Exception {
        this.username = username; // Set username for the session
        String publicKeyB64 = Base64.getEncoder().encodeToString(this.rsaKeyPair.getPublic().getEncoded());
        LoginPayload payload = new LoginPayload(username, password, publicKeyB64); // Use constructor that includes the key
        String jsonPayload = new Gson().toJson(payload);

        IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
        String encryptedPayload = AESEncryptionUtil.encrypt(jsonPayload.getBytes(), this.aesKey, iv);

        Message loginMessage = new Message(
                MessageType.LOGIN,
                username,
                "server",
                encryptedPayload,
                iv.getIV(),
                System.currentTimeMillis()
        );
        networkManager.sendData(loginMessage);
    }

    /**
     * Registers a new user account.
     * Sends the username, password, and the client's public RSA key to the server.
     * @param username The desired username.
     * @param password The password for the new account.
     * @throws Exception if the registration request fails.
     */
    public void register(String username, String password) throws Exception {
        this.username = username;
        // Encode the client's public RSA key to send during registration
        String publicKeyB64 = Base64.getEncoder().encodeToString(this.rsaKeyPair.getPublic().getEncoded());
        LoginPayload payload = new LoginPayload(username, password, publicKeyB64); // Assuming you add publicKey to LoginPayload
        String jsonPayload = new Gson().toJson(payload);

        // Encrypt payload with server session key
        IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
        String encryptedPayload = AESEncryptionUtil.encrypt(jsonPayload.getBytes(), this.aesKey, iv);

        Message registerMessage = new Message(
                MessageType.REGISTER,
                username,
                "server",
                encryptedPayload,
                iv.getIV(),
                System.currentTimeMillis()
        );
        networkManager.sendData(registerMessage);
    }

    public void logout() {
        if (networkManager != null && this.username != null) {
            try {
                String payload = "User " + this.username + " is logging out!!";
                IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                String encryptedPayload = AESEncryptionUtil.encrypt(payload.getBytes(), this.aesKey, iv);
                Message message = new Message(
                        LOGOUT,
                        username,
                        "server",
                        encryptedPayload,
                        iv.getIV(),
                        System.currentTimeMillis()
                );
                networkManager.sendData(message);
                System.out.println("Logout information was sent to server");
            } catch (Exception e) {
                System.err.println("Error while logging out ");
            } finally {
                disconnect();
            }
        }
    }

    public void setKickedListener(KickedListener listener) { // <-- DODAJ TEN SETTER
        this.kickedListener = listener;
    }

    public void setSessionStateListener(SessionStateListener listener) {
        this.sessionListener = listener;
    }

    public void setAuthListener(AuthListener listener) {
        this.authListener = listener;
    }

    // Metody do ustawiania listenerów
    public void setMessageReceivedListener(MessageReceivedListener listener) {
        this.messageListener = listener;
    }

    public void setUserListListener(UserListListener listener) {
        this.userListListener = listener;
        if (this.userListListener != null && this.bufferedUserList != null) {
            System.out.println("Listener is ready. Applying buffered user list.");
            this.userListListener.onUserListUpdated(this.bufferedUserList);
            this.bufferedUserList = null;
        }
    }

    // this method creat ConnectionStatusListener and implements creatConnectionStatusListener.
    private ConnectionStatusListener creatConnectionStatusListener() {
        return new ConnectionStatusListener() {
            @Override
            public void onConnectionStatusChanged(boolean connected) {
                if (connected) {
                    System.out.println("client connected to server.");
                } else {
                    System.out.println("client disconnected from server.");
                }
            }
        };
    }

    @Override
    public void onConnectionLost() {
        System.err.println("Connection to server lost.");
        if (connectionStatusListener != null) {
            connectionStatusListener.onConnectionStatusChanged(false);
        }
    }


    public void setConnectionStatusListener(ConnectionStatusListener listener) {
        this.connectionStatusListener = creatConnectionStatusListener();

    }

    /**
     * A listener for updates to the online user list.
     */
    public interface UserListListener {
        void onUserListUpdated(Set<User> users);
    }

    // nowy listener dla wiadomosci typu ERROR
    public interface ErrorListener {
        void onErrorReceived(String errorMessage);
    }

    public void setErrorListener(ErrorListener listener) {
        this.errorListener = listener;
    }

    public interface SessionStateListener {
        void onSessionEstablished();

        void onSessionFailed(String reason);
    }

    /**
     * A listener for authentication-related events (login/register success or failure).
     */
    public interface AuthListener {
        void onLoginSuccess();

        void onLoginFailure(String reason);

        void onRegisterSuccess();

        void onRegisterFailure(String reason);
    }

    public interface ConnectionStatusListener {
        void onConnectionStatusChanged(boolean connected);
    }

    public interface KickedListener {
        void onKicked(String reason);
    }


    public String getUsername() {
        return this.username;
    }

}


