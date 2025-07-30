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
        networkManager.sendData(aesKeyMessage);
        System.out.println("An encrypted AES key was sent.");
        clientAESKeySent = true;
    }

    /**
     * Processes incoming messages from the server.
     * This method is the core message handler that routes different message types
     * to the appropriate processing logic and notifies relevant listeners.
     * @param message The incoming message to process
     */
    private void handleIncomingMessage(Message message) {
        switch (message.getType()) {
            case PUBLIC_KEY_EXCHANGE:
                try {
                    String publicKeyEncoded = message.getPayload();
                    this.serverRSAPublicKey = RSAEncryptionUtil.decodePublicKey(publicKeyEncoded);
                    System.out.println("The server's RSA key has been received.");
                    sendClientAESKey();
                } catch (Exception e) {
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
                    String sender = message.getSender();
                    byte[] encryptedAESKey = Base64.getDecoder().decode(message.getPayload());

                    byte[] decryptedAESKeyBytes = RSAEncryptionUtil.decryptRSA(encryptedAESKey, this.rsaKeyPair.getPrivate());
                    SecretKey sharedKey = new SecretKeySpec(decryptedAESKeyBytes, 0, decryptedAESKeyBytes.length, "AES");
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
                SecretKey conversationKey = conversationKeys.get(message.getSender());
                if (conversationKey != null) {
                    try {
                        IvParameterSpec iv = new IvParameterSpec(message.getEncryptedIv());
                        String content = AESEncryptionUtil.decrypt(message.getPayload(), conversationKey, iv);
                        System.out.println("Decrypted E2E message from " + message.getSender() + ": " + content);
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
            case ERROR:
                String errorMessage = decryptedPayload(message);
                System.err.println("ERROR from server: " + errorMessage);
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
/**
 * Decrypts the payload of a message using the client-server AES session key.
 *
 * <p>This method takes an encrypted message and uses the client's AES session key
 * along with the Initialization Vector (IV) contained in the message to decrypt
 * the payload. This is used for messages exchanged directly with the server.</p>
 *
 *
 * @param message The encrypted message to decrypt
 * @return The decrypted payload as a string, or null if decryption fails
 * @throws RuntimeException if a decryption error occurs
 * @deprecated This method should not be in ChatClient class.!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
 @Deprecated
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
    /**
     * Logs the user out of the system.
     * Sends a logout message to the server, then disconnects the client.
     * This method will clean up resources even if sending the logout message fails.
     */
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

    /**
     * Sets a listener for handling user kick events.
     * This listener is notified when the server kicks the user from the system.
     * @param listener The KickedListener implementation to handle kick events
     */
    public void setKickedListener(KickedListener listener) {
        this.kickedListener = listener;
    }

    /**
     * Sets a listener for secure session state changes.
     * This listener is notified when the secure session with the server is established or fails.
     * @param listener The SessionStateListener implementation to handle session state events
     */
    public void setSessionStateListener(SessionStateListener listener) {
        this.sessionListener = listener;
    }

    /**
     * Sets a listener for authentication events.
     * This listener is notified about login and registration successes or failures.
     * @param listener The AuthListener implementation to handle authentication events
     */
    public void setAuthListener(AuthListener listener) {
        this.authListener = listener;
    }

    /**
     * Sets a listener for incoming chat messages.
     * This listener is notified when a message is received from another user.
     * 
     * @param listener The MessageReceivedListener implementation to handle received messages
     */
    public void setMessageReceivedListener(MessageReceivedListener listener) {
        this.messageListener = listener;
    }

    /**
     * Sets a listener for user list updates.
     * This listener is notified when the server sends an updated list of online users.
     * If a list was received before the listener was set, it will be immediately delivered.
     * 
     * @param listener The UserListListener implementation to handle user list updates
     */
    public void setUserListListener(UserListListener listener) {
        this.userListListener = listener;
        if (this.userListListener != null && this.bufferedUserList != null) {
            System.out.println("Listener is ready. Applying buffered user list.");
            this.userListListener.onUserListUpdated(this.bufferedUserList);
            this.bufferedUserList = null;
        }
    }

    /**
     * Creates a default implementation of the ConnectionStatusListener.
     * This implementation simply logs connection status changes to the console.
     * 
     * @return A new ConnectionStatusListener instance
     */
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

    /**
     * Handles the event when the connection to the server is lost.
     * This method is called by the {@link ClientNetworkManager} when it detects a connection loss.
     * It notifies the connection status listener about the disconnection.
     */
    @Override
    public void onConnectionLost() {
        System.err.println("Connection to server lost.");
        if (connectionStatusListener != null) {
            connectionStatusListener.onConnectionStatusChanged(false);
        }
    }


    /**
     * Sets a listener for connection status changes.
     * Currently this method ignores the provided listener and uses a default implementation.
     * 
     * @param listener The ConnectionStatusListener implementation (currently ignored)
     */
    public void setConnectionStatusListener(ConnectionStatusListener listener) {
        this.connectionStatusListener = creatConnectionStatusListener();
    }

    /**
     * A listener for updates to the online user list.
     */
    public interface UserListListener {
        void onUserListUpdated(Set<User> users);
    }

    /**
     * Interface for handling secure session state events.
     * Implementations receive notifications about session establishment success or failure.
     */
    public interface SessionStateListener {
        /**
         * Called when a secure session with the server has been successfully established.
         */
        void onSessionEstablished();

        /**
         * Called when a secure session with the server failed to be established.
         * 
         * @param reason The reason for the session establishment failure
         */
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

    /**
     * Interface for handling connection status change events.
     * Implementations receive notifications when the client connects to or disconnects from the server.
     */
    public interface ConnectionStatusListener {
        /**
         * Called when the connection status changes.
         * 
         * @param connected true if the client is now connected, false if disconnected
         */
        void onConnectionStatusChanged(boolean connected);
    }

    /**
     * Interface for handling user kick events.
     * Implementations receive notifications when the user is kicked from the server.
     */
    public interface KickedListener {
        /**
         * Called when the user is kicked from the server.
         * 
         * @param reason The reason why the user was kicked
         */
        void onKicked(String reason);
    }

    /**
     * Gets the username of the currently logged-in user.
     * 
     * @return The username of the current user, or null if not logged in
     */
    public String getUsername() {
        return this.username;
    }

}


