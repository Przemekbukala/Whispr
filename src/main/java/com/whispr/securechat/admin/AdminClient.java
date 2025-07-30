package com.whispr.securechat.admin;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.whispr.securechat.client.networking.ClientNetworkManager;
import com.whispr.securechat.common.*;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Set;
import static com.whispr.securechat.common.MessageType.*;
import static com.whispr.securechat.security.RSAEncryptionUtil.encryptRSA;

/**
 * AdminClient class provides administrative functionality for the secure chat application.
 * It establishes a secure connection with the server using RSA and AES encryption for
 * managing users, viewing logs, and performing administrative tasks.
 * This client handles communication with the server through a secure channel and
 * implements the ClientNetworkManager.MessageReceiver interface to process incoming messages.
 */
public class AdminClient implements ClientNetworkManager.MessageReceiver {
    private ClientNetworkManager networkManager;
    private String serverAddress;
    private int serverPort;
    private KeyPair rsaKeyPair; // Para kluczy RSA klienta
    private PublicKey serverRSAPublicKey; // Klucz publiczny RSA serwera
    private boolean adminPublicKeySent = false;
    private boolean adminAESKeySent = false;
    private SecretKey aesAdminKey;
    private AdminClientListener listener;
    private final Gson gson = new Gson();

    /**
     * Constructs a new AdminClient with the specified server address.
     * Initializes the RSA key pair and sets the server port to the default value.
     * @param serverAddress The IP address or hostname of the server to connect to.
     * @throws RuntimeException If there is an error, while generating the RSA key pair.
     */
    public AdminClient(String serverAddress) {
        this.serverPort = Constants.SERVER_PORT;
        this.serverAddress = serverAddress;
        try {
            this.rsaKeyPair = RSAEncryptionUtil.generateRSAKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    /**
     * Establishes a connection to the server and initiates the secure "handshake process".
     * This method creates a socket connection to the server, initializes the network manager,
     * and sends the admin's public key to begin the secure communication process.
     * The method starts a new thread for the network manager to handle incoming messages.
     * @throws RuntimeException If there is an error, while sending Admin public key.
     */
    public void connect() {
        try {
            Socket socket = new Socket(this.serverAddress, this.serverPort);
            this.networkManager = new ClientNetworkManager(socket);
            this.networkManager.setMessageReceiver(this);
            new Thread(this.networkManager).start();
            System.out.println("Connected with server: " + serverAddress +
                    ":" + serverPort);
            try {
                sendAdminPublicKey();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } catch (IOException e) {
            System.err.println("Error while connecting to server: " + e.getMessage());
        }
    }

    /**
     * Sends an admin login request to the server.
     * This method encrypts the admin credentials using AES encryption and sends them to the server.
     * The login request includes the admin's username, password, and public RSA key.
     * The AES key must be established before calling this method.
     * @param username The admin username for authentication.
     * @param password The admin password for authentication.
     */
    public void sendAdminLogin(String username, String password) {
        if (aesAdminKey == null) {
            System.err.println("AdminClient: AES key has not yet been set. The login cannot be sent.");
            return;
        }

        try {
            String publicKeyB64 = Base64.getEncoder().encodeToString(this.rsaKeyPair.getPublic().getEncoded());
            LoginPayload payload = new LoginPayload(username, password, publicKeyB64); // Use constructor that includes the key
            String jsonPayload = new Gson().toJson(payload);

            IvParameterSpec IV = AESEncryptionUtil.generateIVParameterSpec();
            String encryptedPayload = AESEncryptionUtil.encrypt(jsonPayload.getBytes(), this.aesAdminKey, IV);
            Message loginMessage = new Message(
                    MessageType.ADMIN_LOGIN,
                    "admin",
                    "server",
                    encryptedPayload, IV.getIV(),
                    System.currentTimeMillis()
            );
            networkManager.sendData(loginMessage);
            System.out.println("AdminClient: Encrypted admin login request sent.");
        } catch (Exception e) {
            System.err.println("AdminClient: Error while encrypting or sending admin login.");
            e.printStackTrace();
        }
    }
    /**
     * Processes incoming messages from the server.
     * This method handles various types of messages including public key exchange, AES key exchange,
     * server information, error messages, log messages, and user list updates.
     * Depending on the message type, it will perform the appropriate action and notify listeners
     * when necessary.
     * @param message The received message from the server
     */
    @Override
    public void onMessageReceived(Message message) {
        MessageType messageType = message.getType();
        switch (messageType) {
            case PUBLIC_KEY_EXCHANGE:
                try {
                    String publicKeyEncoded = message.getPayload();
                    this.serverRSAPublicKey = RSAEncryptionUtil.decodePublicKey(publicKeyEncoded);
                    System.out.println("Server public RSA key received.");
                    sendAdminAESKey();
                } catch (Exception e) {
                    System.err.println("Error during public key exchange: " + e.getMessage());
                    throw new RuntimeException(e);
                }
                break;
            case AES_KEY_EXCHANGE:
                System.out.println("Server acknowledged AES key. Session should be ready.");
                break;
            case SERVER_INFO:
            case ERROR:
                try {
                    String decryptedMessage = EncryptionUtil.decryptedPayload(message,this.aesAdminKey);
                    System.out.println("AdminClient received decrypted message: " + decryptedMessage);
                    if (listener == null) {
                        System.err.println("AdminClient: Listener is not set, cannot dispatch message.");
                        return;
                    }
                    // Rozróżniamy komunikaty na podstawie ich treści.
                    if (decryptedMessage.equals("AES key received successfully. Session ready!")) {
                        listener.onSessionReady();
                    } else if (messageType == SERVER_INFO) {
                        listener.onLoginResponse(true, decryptedMessage);
                    } else { // messageType == ERROR
                        listener.onLoginResponse(false, decryptedMessage);
                    }

                } catch (Exception e) {
                    System.err.println("Error decrypting server message: " + e.getMessage());
                    if (listener != null) {
                        listener.onLoginResponse(false, "Failed to decrypt server response.");
                    }
                }
                break;

            case ADMIN_LOG_MESSAGE:
                if (listener != null) {
                    try {
                        String logMessage = EncryptionUtil.decryptedPayload(message,this.aesAdminKey);
                        listener.onNewLogMessage(logMessage);
                    } catch (Exception e) {
                        System.err.println("Failed to decrypt log message from server.");
                    }
                }
                break;
            case ADMIN_USER_LIST_UPDATE:
                Gson gson = new Gson();
                String decryptedPayload = EncryptionUtil.decryptedPayload(message,this.aesAdminKey);
                Type userSetType = new TypeToken<Set<User>>() {
                }.getType();
                Set<User> users = gson.fromJson(decryptedPayload, userSetType);
                System.out.println("ADMIN_CLIENT: Deserialized users: " + users.size());

                if (listener != null) {
                    listener.onUserListUpdated(users);
                }
                break;
        }
    }

    /**
     * Sends a request to kick a user from the chat server.
     * This method encrypts the username of the user to be kicked using the admin's AES key
     * and sends the request to the server. The server will  disconnect the specified user.
     * @param usernameToKick The username of the user to be kicked from the server
     */
    public void sendKickUserRequest(String usernameToKick) {
        if (aesAdminKey == null) {
            System.err.println("AdminClient: Cannot send kick request, session not ready.");
            return;
        }
        try {
            IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
            String encryptedPayload = AESEncryptionUtil.encrypt(usernameToKick.getBytes(), this.aesAdminKey, iv);
            Message kickRequest = new Message(
                    MessageType.ADMIN_KICK_USER,
                    "admin",
                    "server",
                    encryptedPayload,
                    iv.getIV(),
                    System.currentTimeMillis()
            );
            networkManager.sendData(kickRequest);
        } catch (Exception e) {
            System.err.println("Error sending kick user request for " + usernameToKick);
            e.printStackTrace();
        }
    }
    /**
     * Sends a request to reset a user's password.
     * This method encrypts the password reset request containing the username and new password
     * using the admin's AES key and sends it to the server. The server will then update the
     * user's password in the database.
     * @param username The username of the user whose password will be reset
     * @param newPassword The new password to set for the user
     */
    public void sendResetPasswordRequest(String username, String newPassword) {
        if (aesAdminKey == null) {
            System.err.println("AdminClient: Cannot send reset password request, session not ready.");
            return;
        }
        try {
            PasswordResetPayload payload = new PasswordResetPayload(username, newPassword);
            String jsonPayload = gson.toJson(payload);

            IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
            String encryptedPayload = AESEncryptionUtil.encrypt(jsonPayload.getBytes(), this.aesAdminKey, iv);

            Message resetRequest = new Message(
                    MessageType.ADMIN_RESET_PASSWORD,
                    "admin",
                    "server",
                    encryptedPayload,
                    iv.getIV(),
                    System.currentTimeMillis()
            );
            networkManager.sendData(resetRequest);
        } catch (Exception e) {
            System.err.println("Error sending reset password request for " + username);
            e.printStackTrace();
        }
    }
    /**
     * Generates and sends the admin's AES session key to the server.
     * <p>
     * This method generates a new AES key for the admin session, encrypts it using
     * the server's RSA public key, and sends it to the server.
     * <p>
     * This method is synchronized to prevent concurrent key generation and sending.
     * @throws Exception If an error occurs during key generation, encryption, or sending encrypted AES key to server,
     */
    private synchronized void sendAdminAESKey() throws Exception {
        if (adminAESKeySent) {
            System.out.println("Klucz AES was already sent");
            return;
        }
        if (serverRSAPublicKey == null) {
            System.err.println("Server's RSA public key not established. Cannot send AES key.");
            return;
        }

        this.aesAdminKey = AESEncryptionUtil.generateAESKey();
        System.out.println("AdminClient: AES session key generated.");
        assert this.aesAdminKey != null;
        byte[] encryptedAesKey = encryptRSA(this.aesAdminKey.getEncoded(), this.serverRSAPublicKey);
        String encryptedAesKeyBase64 = Base64.getEncoder().encodeToString(encryptedAesKey);

        Message aesKeyMessage = new Message(
                MessageType.AES_KEY_EXCHANGE,
                "admin",
                "server",
                encryptedAesKeyBase64,
                System.currentTimeMillis()
        );
        networkManager.sendData(aesKeyMessage);
        adminAESKeySent = true;
        System.out.println("AdminClient: AES encrypted key sent to server.");
    }

    /**
     * Sends the admin's RSA public key to the server.
     * <p>
     * This method encodes the admin's RSA public key as a Base64 string and sends it to the server
     * as part of the key exchange process. This is the first step in establishing a secure
     * communication channel between the admin client and server.
     * <p>
     * This method is synchronized to prevent concurrent key sending.
     * @throws Exception If an error occurs during key encoding or sending
     */
    private synchronized void sendAdminPublicKey() throws Exception {
        if (rsaKeyPair == null || rsaKeyPair.getPublic() == null) {
            System.err.println("Client public key could not be found.");
            return;
        }
        if (adminPublicKeySent) {
            System.out.println("Client public key already sent");
            return;
        }

        Message message = new Message(PUBLIC_KEY_EXCHANGE, "admin",
                "server", Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()),
                System.currentTimeMillis());
        networkManager.sendData(message);
        adminPublicKeySent = true;
        System.out.println("AdminClient: Admin public key sent to server.");

    }
    /**
     * Sets the listener for handling admin client events.
     * <p>
     * The listener will be notified of various events such as session readiness,
     * login responses, user list updates, and new log messages.
     * @param listener The AdminClientListener implementation to receive event notifications.
     */
    public void setListener(AdminClientListener listener) {
        this.listener = listener;
    }
}
