package com.whispr.securechat.admin;

import com.google.gson.Gson;
import com.whispr.securechat.client.networking.ClientNetworkManager;
import com.whispr.securechat.common.Constants;
import com.whispr.securechat.common.LoginPayload;
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.MessageType;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

import static com.whispr.securechat.common.Constants.ADMIN_PASSWORD;
import static com.whispr.securechat.common.MessageType.*;
import static com.whispr.securechat.security.RSAEncryptionUtil.encryptRSA;

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
                Thread.sleep(300);
                sendAdminAESKey();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } catch (IOException e) {
            System.err.println("Error while connecting to server: " + e.getMessage());
        }
    }

    public void sendAdminLogin(String username, String password) {
        if (aesAdminKey == null) {
            System.err.println("AdminClient: AES key has not yet been set. The login cannot be sent.");
            return;
        }

        try {
            String publicKeyB64 = Base64.getEncoder().encodeToString(this.rsaKeyPair.getPublic().getEncoded());
            LoginPayload payload = new LoginPayload(username, password, publicKeyB64); // Use constructor that includes the key
            String jsonPayload = new Gson().toJson(payload);

            // This part remains the same
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

    @Override
    public void onMessageReceived(Message message) {
        MessageType messageType = message.getType();

        switch (messageType) {
            case PUBLIC_KEY_EXCHANGE:
                try {
                    String publicKeyEncoded = message.getPayload();
                    this.serverRSAPublicKey = RSAEncryptionUtil.decodePublicKey(publicKeyEncoded);
                    System.out.println("Server public RSA key received.");
                    sendAdminPublicKey(); // GENERALNIE TAM JEST Flaga wiec to nic nie robi wiec trzeba sprawdzic czy bez tego działą jak działą to usunac


                } catch (Exception e) {
                    System.err.println("Error during public key exchange: " + e.getMessage());
                    throw new RuntimeException(e);
                }
                break;

            case AES_KEY_EXCHANGE:
                try {
                    sendAdminAESKey();  //znow tutaj flaga adminAESKeySent  jest true wiec nic nie robi bo  w domysle admin wysyła AES
                } catch (Exception e) {
                    System.err.println("Błąd podczas wysyłania AES Key");
                    e.printStackTrace();
                }
                break;

            case SERVER_INFO:
            case ERROR:
                // Obsługujemy zarówno SERVER_INFO (sukces) jak i ERROR (porażka logowania).
                // W obu przypadkach payload jest zaszyfrowany.
                try {
                    String decryptedMessage = decryptedPayload(message);
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

    // w teorii tą metode mozna włozyc do klasy Message tylko paramatry trzba dodac dodatkowe (identyczna  jak w ChatCLient)
    public String decryptedPayload(Message message) {
        if (this.aesAdminKey == null) {
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
            decryptedPayload = AESEncryptionUtil.decrypt(message.getPayload(), this.aesAdminKey, IV);
        } catch (Exception e) {
            System.err.println("Błąd podczas deszyfrowania wiadomości AES: " + e.getMessage());
            throw new RuntimeException(e);
        }
        return decryptedPayload;
    }

    private synchronized void sendAdminAESKey() throws Exception {
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
        System.out.println("AdminClient: AES encrypted key sent to server.");

        if (serverRSAPublicKey == null) {
            System.err.println("Server`s RSA public key not established.");
            return;
        }
        if (adminAESKeySent) {
            System.out.println("Klucz AES was already sent");
            return;
        }
        // Sending the message
        networkManager.sendData(aesKeyMessage);
        adminAESKeySent = true;
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
                "server", Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()),
                System.currentTimeMillis());
        networkManager.sendData(message);
        adminPublicKeySent = true;
        System.out.println("AdminClient: Admin public key sent to server.");

    }

    public void setListener(AdminClientListener listener) {
        this.listener = listener;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("--- AdminClient Test ---");
        AdminClient adminClient = new AdminClient("localhost");

        // 1. Nawiąż połączenie i poczekaj na wymianę kluczy
        adminClient.connect();
        System.out.println("Connecting and performing key exchange...");
        Thread.sleep(1000); // Dajmy sekundę na wymianę kluczy RSA/AES

        // 2. Pobierz dane logowania z konsoli
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter admin username: ");
        String username = scanner.nextLine();
        System.out.print("Enter admin password: ");
        String password = scanner.nextLine();
        scanner.close();

        // 3. Wyślij prośbę o zalogowanie
        System.out.println("Sending login request for user: " + username);
        adminClient.sendAdminLogin(username, password);
    }
}
