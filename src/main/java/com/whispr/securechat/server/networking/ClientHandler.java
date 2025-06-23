package com.whispr.securechat.server.networking;

import java.io.IOException;
import java.net.Socket;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.whispr.securechat.common.*;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.server.ChatServer; // Może potrzebować dostępu do ClientManager

import static com.whispr.securechat.security.RSAEncryptionUtil.decryptRSA;
import static com.whispr.securechat.security.RSAEncryptionUtil.isBase64;
import static com.whispr.securechat.server.ChatServer.log;

/**
 * Handles all communication with a single client on a dedicated thread.
 * This class is responsible for the entire lifecycle of a client connection,
 * including key exchange, authentication, message processing, and disconnection.
 */
public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private final ChatServer server; // Referencja do serwera
    private final ObjectInputStream objectIn;
    private final ObjectOutputStream objectOut;
    private static final Gson gson = new Gson();
    private static final Logger handlerLog = LoggerFactory.getLogger(ClientHandler.class);

    private String username;
    private SecretKey aesKey; // Klucz AES dla tej sesji klienta
    private final PrivateKey serverRSAPrivateKey; // Prywatny klucz RSA serwera
    private PublicKey clientRSAPublicKey;
    private boolean isAdmin = false;

    /**
     * Constructs a new ClientHandler.
     *
     * @param socket             The client's socket connection.
     * @param server             A reference to the main ChatServer instance.
     * @param serverRSAPrivateKey The server's private RSA key for decrypting session keys.
     * @throws IOException if an I/O error occurs when creating input/output streams.
     */
    public ClientHandler(Socket socket, ChatServer server, PrivateKey serverRSAPrivateKey) throws IOException {
        this.clientSocket = socket;
        this.server = server;
        this.serverRSAPrivateKey = serverRSAPrivateKey;
        this.objectOut = new ObjectOutputStream(clientSocket.getOutputStream());
        this.objectIn = new ObjectInputStream(clientSocket.getInputStream());
    }

    /**
     * The main execution loop for the client thread.
     * Listens for incoming {@link Message} objects, passes them to {@link #handleMessage(Message)},
     * and handles disconnection and cleanup.
     */
    @Override
    public void run() {
        // Główna pętla wątku, odczytująca i przetwarzająca wiadomości od klienta
        try {
            while (true) {
                try {
                    Message message = (Message) objectIn.readObject();
                    if (message != null) {
                        try {
                            handleMessage(message);
                        } catch (Exception e) {
                            handlerLog.error("Error handling message from user '{}': {}", username, message, e);
                            sendEncryptedFailureMessage("An internal error occurred while processing your request.");
                            break;
                        }
                        System.out.println(message);
                    }
                } catch (IOException e) {
                    String clientIdentifier = (username != null) ? username : "unauthenticated client";
                    System.err.println("Client " + clientIdentifier + " @ " + clientSocket.getInetAddress().getHostAddress() + " disconnected.");
                    handlerLog.info("Client {} @ {} disconnected.", clientIdentifier, clientSocket.getInetAddress().getHostAddress());
                    server.getClientManager().broadcastLogToAdmins("Client '" + clientIdentifier + "' disconnected.");
                    if (username != null) {
                        if (isAdmin) {
                            server.getClientManager().removeAdmin(username);
                        } else {
                            server.getClientManager().removeClient(username);
                        }
                    }
                    break;
                } catch (ClassNotFoundException e) {
                    System.err.println("Received unknown object type from client " + clientSocket.getInetAddress().getHostAddress() + ": " + e.getMessage());
                    handlerLog.error("Received unknown object type from client {}: {}", clientSocket.getInetAddress().getHostAddress(), e.getMessage());
                    break;
                }
            }
        } finally {
            System.err.println("Closing connection for client: " + clientSocket.getInetAddress().getHostAddress());
            handleLogout();
        }
    }

    /**
     * Decrypts the payload of a message using the established AES session key.
     *
     * @param message The message with an encrypted payload.
     * @return The decrypted plaintext payload as a String.
     * @throws Exception if the AES key is not established or decryption fails.
     */
    public String decryptChatMessage(Message message) throws Exception {
        if (this.aesKey == null) {
            throw new IllegalStateException("AES key not established for: " + username);
        }
        IvParameterSpec iv = new IvParameterSpec(message.getEncryptedIv());
        return AESEncryptionUtil.decrypt(message.getPayload(), this.aesKey, iv);
    }

    /**
     * Sends a {@link Message} object to the connected client.
     *
     * @param message The message to send.
     * @throws IOException if an I/O error occurs while sending the message.
     */
    public void sendMessage(Message message) throws Exception {
        if (!clientSocket.isClosed() && objectOut != null) {
            objectOut.writeObject(message);
            objectOut.flush();
        } else {
            System.err.println("Attempted to send a message to a closed socket for user: " + username);
        }
    }

    /**
     * Gets the username of the authenticated client.
     * @return The username, or null if not authenticated.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the username for this handler, typically after successful authentication.
     * @param username The username to set.
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Gets the AES session key established with this client.
     * @return The client's {@link SecretKey}.
     */
    public SecretKey getAesKey() {
        return aesKey;
    }

    /**
     * Gets the underlying socket for this client connection.
     * @return The client's {@link Socket}.
     */
    public Socket getClientSocket() {
        return clientSocket;
    }

    /**
     * Sends the server's public RSA key to the client.
     * This is a crucial step in the cryptographic handshake, allowing the client
     * to securely send back the AES session key.
     */
    void sendPublicRSAKey() {
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

    /**
     * Processes an incoming message by routing it to the appropriate handler method based on its type.
     * Enforces that clients must authenticate before sending most message types.
     *
     * @param message The incoming message from the client.
     * @throws Exception if any error occurs during message handling.
     */
    private void handleMessage(Message message) throws Exception {
        // Zbiór typów wiadomości dozwolonych przed zalogowaniem
        Set<MessageType> allowedPreAuthMessages = Set.of(
                MessageType.PUBLIC_KEY_EXCHANGE,
                MessageType.AES_KEY_EXCHANGE,
                MessageType.LOGIN,
                MessageType.REGISTER,
                MessageType.ADMIN_LOGIN
        );

        if (this.username == null && !allowedPreAuthMessages.contains(message.getType())) {
            System.err.println("Received unauthorized message of type " + message.getType() + " from unauthenticated client. Disconnecting.");
            clientSocket.close();
            return;
        }

        switch (message.getType()) {
            case PUBLIC_KEY_EXCHANGE:
                handlePublicKeyExchange(message);
                break;
            case AES_KEY_EXCHANGE:
                handleAESKeyExchange(message);
                break;
            case LOGOUT:
                handleLogout();
                break;
            case LOGIN:
                handleLogin(message);
                break;
            case REGISTER:
                handleRegistration(message);
                break;
            case CHAT_MESSAGE:
            case E2E_SESSION_KEY_SHARE:
//                System.out.println("Forwarding an E2E messege from: " + message.getSender()
//                        + " to " + message.getRecipient());
                server.getClientManager().forwardMessage(message);
                break;
            case E2E_PUBLIC_KEY_REQUEST:
                handlePublicKeyRequest(message);
                break;
            case ADMIN_LOGIN:
                handleAdminLogin(message);
                break;
            case ADMIN_KICK_USER:
                handleAdminKickUser(message);
                break;
            case ADMIN_RESET_PASSWORD:
                handleAdminResetPassword(message);
                break;
            // TU moze dodac waidomosc do klienta ze otryzmal to co chciał
            default:
                System.err.println("Received unknow message type: " + message.getType());
        }
    }

    /**
     * Handles receiving the client's public RSA key and sending back the server's public key.
     * @param message The PUBLIC_KEY_EXCHANGE message.
     * @throws Exception on key decoding failure.
     */
    private void handlePublicKeyExchange(Message message) throws Exception{
        try {
            String clientRSA = message.getPayload();
            this.clientRSAPublicKey = RSAEncryptionUtil.decodePublicKey(clientRSA);
            System.out.println("Received and saved the RSA public key from the client: ");
        } catch (Exception e) {
            System.err.println("Error while decoding client's public key:" + e.getMessage());
            throw e;
        }
        sendPublicRSAKey();
    }

    /**
     * Handles receiving the client's encrypted AES session key.
     * @param message The AES_KEY_EXCHANGE message.
     */
    private void handleAESKeyExchange(Message message){
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
    }

    /**
     * Handles a request from an admin to kick a user.
     * @param message The ADMIN_KICK_USER message.
     */
    private void handleAdminKickUser(Message message) {
        if (this.isAdmin) {
            try {
                String usernameToKick = decryptChatMessage(message);
                server.getClientManager().kickUser(usernameToKick, this.username);
            } catch (Exception e) {
                System.err.println("Admin " + this.username + " failed to process kick request.");
                server.getClientManager().broadcastLogToAdmins("Failed to kick User '" + username);
                e.printStackTrace();
            }
        }
    }

    /**
     * Handles a request from an admin to reset a user's password.
     * @param message The ADMIN_RESET_PASSWORD message.
     */
    private void handleAdminResetPassword(Message message) {
        if (this.isAdmin) {
            try {
                String decryptedPayload = decryptChatMessage(message);
                PasswordResetPayload payload = gson.fromJson(decryptedPayload, PasswordResetPayload.class);
                String usernameToReset = payload.getUsername();
                String newPassword = payload.getNewPassword();

                boolean success = server.getDbManager().resetUserPassword(usernameToReset, newPassword);

                if (success) {
                    server.getClientManager().broadcastLogToAdmins("Admin '" + this.username + "' successfully reset password for user '" + usernameToReset + "'.");
                } else {
                    server.getClientManager().broadcastLogToAdmins("Admin '" + this.username + "' FAILED to reset password for user '" + usernameToReset + "'.");
                }
            } catch (Exception e) {
                System.err.println("Admin " + this.username + " failed to process password reset request.");
                server.getClientManager().broadcastLogToAdmins("Error processing password reset from admin '" + this.username + "'.");
                e.printStackTrace();
            }
        }
    }

    /**
     * Handles a request from a client for another user's public key for E2E encryption.
     * @param message The E2E_PUBLIC_KEY_REQUEST message.
     * @throws Exception on failure to send response.
     */
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

    /**
     * Handles a login attempt from a client.
     * @param message The LOGIN message.
     */
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
                boolean successfullyUpdatedKey = server.getDbManager().updateUserPublicKey(username, publicKey);
                if (!successfullyUpdatedKey) throw new RuntimeException("Error updating keys for User: " + username);
                this.username = username;
                server.getClientManager().addClient(username, this);
                server.getClientManager().broadcastLogToAdmins("User '" + username + "' logged in successfully.");

                IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                String payloadToEncrypt = "Logged successfully!";
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, iv);

                Message loginConfirmationMessage = new Message(
                        MessageType.LOGIN_SUCCESS,
                        "server",
                        username,
                        encryptedData,
                        iv.getIV(),
                        System.currentTimeMillis());
                sendMessage(loginConfirmationMessage);
                server.getClientManager().notifyClientsOfUserListChange();
            } else {
                IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                String payloadToEncrypt = "Username or password incorrect!";
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, iv);

                Message loginRejectionMessage = new Message(
                        MessageType.LOGIN_FAILURE,
                        "server",
                        username,
                        encryptedData,
                        iv.getIV(),
                        System.currentTimeMillis());
                sendMessage(loginRejectionMessage);
                server.getClientManager().broadcastLogToAdmins("Failed login attempt for username: '" + username + "'.");
            }
        } catch (Exception e) {
            System.err.println("Error during login process for user: " + username);
            e.printStackTrace();
            try {
                String payloadToEncrypt = "Server error during login.";
                IvParameterSpec errorIV = AESEncryptionUtil.generateIVParameterSpec();
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, errorIV);
                String recipient = (username != null) ? username : message.getSender();
                Message loginErrorMessage = new Message(
                        MessageType.LOGIN_FAILURE,
                        "server",
                        recipient,
                        encryptedData,
                        errorIV.getIV(),
                        System.currentTimeMillis());
                sendMessage(loginErrorMessage);
            } catch (Exception ex) {
                System.err.println("Failed to send error message to client: " + ex.getMessage());
            }
        }
    }

    /**
     * Handles a registration attempt from a client.
     * @param message The REGISTER message.
     */
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
                Message successfulRegistration = new Message(
                        MessageType.REGISTER_SUCCESS,
                        "server",
                        username,
                        encryptedData,
                        iv.getIV(),
                        System.currentTimeMillis());
                sendMessage(successfulRegistration);
            } else {
                String payloadToEncrypt = "User with this name already exists.";
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, iv);
                Message failureRegistration = new Message(
                        MessageType.REGISTER_FAILURE,
                        "server",
                        username,
                        encryptedData,
                        iv.getIV(),
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
                Message registrationErrorMessage = new Message(
                        MessageType.REGISTER_FAILURE,
                        "server",
                        recipient,
                        encryptedData,
                        errorIV.getIV(),
                        System.currentTimeMillis());
                sendMessage(registrationErrorMessage);
            } catch (Exception ex) {
                System.err.println("Failed to send error message to client: " + ex.getMessage());
            }
        }
    }

    /**
     * Centralizes the cleanup logic for a client.
     * Removes the client from the ClientManager, notifies others, and closes all resources.
     */
    private void handleLogout() {
        try {
            if (this.username != null) {
                String logMessage;
                if (this.isAdmin) {
                    server.getClientManager().removeAdmin(this.username);
                    logMessage = "Admin '" + this.username + "' logged out.";
                } else {
                    server.getClientManager().removeClient(this.username);
                    logMessage = "User '" + this.username + "' logged out.";
                }
                handlerLog.info(logMessage);
                server.getClientManager().broadcastLogToAdmins(logMessage);

                this.username = null;
                this.aesKey = null;
                this.clientRSAPublicKey = null;
                this.isAdmin = false;
            }
            if (clientSocket != null && !clientSocket.isClosed()) {
                clientSocket.close();
            }
        } catch (Exception e) {
            handlerLog.error("Error during server-side logout for user '{}'", this.username, e);
        } finally {
            try {
                if (objectOut != null) objectOut.close();
                if (objectIn != null) objectIn.close();
                if (clientSocket != null && !clientSocket.isClosed()) clientSocket.close();
            } catch (IOException e) {
                handlerLog.error("Error closing client socket/streams: {}", e.getMessage());
            }
        }
    }

    /**
     * Handles an admin login attempt.
     * @param message The ADMIN_LOGIN message.
     */
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
                log.info("Admin authentication successful for: {}", adminUsername);

                this.isAdmin = true;
                this.username = adminUsername;

                boolean successfullyUpdatedKey = server.getDbManager().updateAdminPublicKey(adminUsername, publicKey);
                if (!successfullyUpdatedKey) throw new RuntimeException("Error updating keys for Admin!");
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

                Message loginRejectionMessage = null;
                if (iv != null) {
                    loginRejectionMessage = new Message(MessageType.ERROR,
                            "server", adminUsername, encryptedData, iv.getIV(),
                            System.currentTimeMillis());
                }
                sendMessage(loginRejectionMessage);
            }
        } catch (Exception e) {
            log.error("Error during admin login process for: {}", adminUsername, e);
            System.err.println("Error during login process for admin: " + adminUsername);
            e.printStackTrace();
            try {
                String payloadToEncrypt = "Server error during admin's login.";
                IvParameterSpec errorIV = AESEncryptionUtil.generateIVParameterSpec();
                String encryptedData = AESEncryptionUtil.encrypt(payloadToEncrypt.getBytes(), this.aesKey, errorIV);
                String recipient = (adminUsername != null) ? adminUsername : message.getSender();
                Message loginErrorMessage = null;
                if (errorIV != null) {
                    loginErrorMessage = new Message(MessageType.ERROR,
                            "server", recipient, encryptedData, errorIV.getIV(),
                            System.currentTimeMillis());
                }
                sendMessage(loginErrorMessage);
            } catch (Exception ex) {
                System.err.println("Failed to send error message to admin client: " + ex.getMessage());
                log.error("Failed to send error message to admin client", ex);
            }
        }
    }

    /**
     * Sends a standardized, encrypted failure message to the client.
     * This helper method uses the established AES session key to encrypt the error details
     * before sending them as a Message of type ERROR.
     *
     * @param errorMessage The human-readable, plaintext error message to be sent to the client.
     */
    private void sendEncryptedFailureMessage(String errorMessage) {
        if (this.aesKey == null) {
            handlerLog.warn("Cannot send encrypted failure message to user '{}', AES session key is not established.", username);
            return;
        }
        try {
            IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
            String encryptedData = AESEncryptionUtil.encrypt(errorMessage.getBytes(), this.aesKey, iv);

            Message failureMessage = null;
            if (iv != null) {
                failureMessage = new Message(
                        MessageType.ERROR,
                        "server",
                        this.username,
                        encryptedData,
                        iv.getIV(),
                        System.currentTimeMillis());
            }
            sendMessage(failureMessage);
        } catch (Exception e) {
            handlerLog.error("Failed to send encrypted failure message to user '{}'", username, e);
        }
    }
}