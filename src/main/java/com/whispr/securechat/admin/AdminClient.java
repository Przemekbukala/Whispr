package com.whispr.securechat.admin;

import com.whispr.securechat.admin.gui.ServerStateListener;
import com.whispr.securechat.client.networking.ClientNetworkManager;
import com.whispr.securechat.common.Constants;
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.MessageType;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;

import static com.whispr.securechat.common.MessageType.*;

public class AdminClient implements ClientNetworkManager.MessageReceiver {
    private ClientNetworkManager networkManager;
    private String serverAddress;
    private int serverPort;
    private KeyPair rsaKeyPair; // Para kluczy RSA klienta
    private PublicKey serverRSAPublicKey; // Klucz publiczny RSA serwera
    private boolean adminPublicKeySent = false;
    private SecretKey aesAdminKey;
    private AdminClientListener listener;
    private ServerStateListener serverStateListener;

    public AdminClient(String serverAddress) {
        this.serverPort = Constants.SERVER_PORT;
        this.serverAddress = serverAddress;
        try {
            this.rsaKeyPair = RSAEncryptionUtil.generateRSAKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

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
//                Thread.sleep(300);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } catch (IOException e) {
            System.err.println("Error while connecting to server: " + e.getMessage());
        }
    }

    public void sendAdminLogin(String password) {
        if (aesAdminKey == null) {
            System.err.println("AdminClient: AES key has not yet been set. The login cannot be sent.");
            return;
        }

        try {
            byte[] encryptedPassword = AESEncryptionUtil.encrypt(password.getBytes(), this.aesAdminKey);
            String payload = RSAEncryptionUtil.encodeToString(encryptedPassword);
            Message loginMessage = new Message(
                    MessageType.ADMIN_LOGIN,
                    "admin",
                    "server",
                    payload,
                    System.currentTimeMillis()
            );
            networkManager.sendData(loginMessage);
            System.out.println("AdminClient: Encrypted admin login request sent.");

        } catch (Exception e) {
            System.err.println("AdminClient: Error while encrypting or sending admin login.");
            e.printStackTrace();
        }
    }

    @Override
    public void onMessageReceived(Message message) {
        MessageType messageType = message.getType();
        System.out.println("DEBUG: Client received message of type: " + messageType);

        switch (messageType) {
            case PUBLIC_KEY_EXCHANGE:
                try {
                    String publicKeyEncoded = message.getPayload();
                    this.serverRSAPublicKey = RSAEncryptionUtil.decodePublicKey(publicKeyEncoded);
                    this.aesAdminKey = AESEncryptionUtil.generateAESKey();
                    System.out.println("AdminClient: AES session key generated.");

                    assert this.aesAdminKey != null;
                    byte[] encryptedAesKey = RSAEncryptionUtil.encrypt(this.aesAdminKey.getEncoded(), this.serverRSAPublicKey);

                    String payload = RSAEncryptionUtil.encodeToString(encryptedAesKey);
                    Message aesMessage = new Message(AES_KEY_EXCHANGE, "admin",
                            "server", payload, System.currentTimeMillis());
                    networkManager.sendData(aesMessage);
                    System.out.println("AdminClient: AES encrypted key sent to server.");

                } catch (Exception e) {
                    System.err.println("Critical error during key exchange: " + e.getMessage());
                    if (listener != null) {
                        // Notify the GUI about the failure instead of crashing the thread
                        listener.onLoginResponse(false, "A critical error occurred during key exchange. Please try again.");
                    }
                }
                break;

            case SERVER_INFO:
            case ERROR:
                // Obsługujemy zarówno SERVER_INFO (sukces) jak i ERROR (porażka logowania).
                // W obu przypadkach payload jest zaszyfrowany.
                try {
                    String encryptedPayload = message.getPayload();
                    byte[] bytePayload = Base64.getDecoder().decode(encryptedPayload);
                    byte[] decryptedPayloadBytes = AESEncryptionUtil.decrypt(bytePayload, this.aesAdminKey);
                    String decryptedMessage = new String(decryptedPayloadBytes, StandardCharsets.UTF_8);
                    System.out.println("DEBUG: Decrypted message content: '" + decryptedMessage + "'");
                    System.out.println("AdminClient received decrypted message: " + decryptedMessage);

                    if (listener == null) {
                        System.err.println("AdminClient: Listener is not set, cannot dispatch message.");
                        return;
                    }
                    // Rozróżniamy komunikaty na podstawie ich treści.
                    if (decryptedMessage.equals("AES key received successfully. Session ready!")) {
                        listener.onSessionReady();
                    } else if (messageType == SERVER_INFO) {
                        // Zakładamy, że inny SERVER_INFO to potwierdzenie udanego logowania.
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

            default:
                System.err.println("AdminClient: Received unhandled message type: " + messageType);
                break;
        }
    }

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
                "server", RSAEncryptionUtil.encodeToString(rsaKeyPair.getPublic().getEncoded()),
                System.currentTimeMillis());
        networkManager.sendData(message);
        adminPublicKeySent = true;
        System.out.println("AdminClient: Admin public key sent to server.");

    }

    public void setListener(AdminClientListener listener) {
        this.listener = listener;
    }

    public void setServerStateListener(ServerStateListener listener) {
        this.serverStateListener = listener;
    }
}
