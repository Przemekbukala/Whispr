package com.whispr.securechat.client;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
// Importy dla exceptionów
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.whispr.securechat.client.networking.ClientNetworkManager;
import com.whispr.securechat.common.MessageType;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.common.Constants;
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.User;

import static com.whispr.securechat.common.MessageType.*;
import static com.whispr.securechat.security.RSAEncryptionUtil.*;


public class ChatClient {
    private String serverAddress;
    private int serverPort;
    private ClientNetworkManager networkManager;
    private String username;
    private SecretKey aesKey; // Klucz AES dla sesji klienta
    private KeyPair rsaKeyPair; // Para kluczy RSA klienta
    private PublicKey serverRSAPublicKey; // Klucz publiczny RSA serwera
    // Callbacki dla GUI (lub event bus)
    private MessageReceivedListener messageListener;
    private UserListListener userListListener;
    private ConnectionStatusListener connectionStatusListener;
    // aby uniknąc zapętlenia
    private boolean clientPublicKeySent = false;
    private boolean clientAESKeySent = false;
    private ConcurrentHashMap<String, SecretKey> conversationKeys;
    private ConcurrentHashMap<String, PublicKey> userPublicKeys;
    private final Gson gson = new Gson();
    private Map<String, Queue<String>> pendingMessages;

    public ChatClient(String serverAddress, int serverPort) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.networkManager = null;
        this.conversationKeys = new ConcurrentHashMap<>();
        this.userPublicKeys = new ConcurrentHashMap<>();

        try {
            this.rsaKeyPair = RSAEncryptionUtil.generateRSAKeyPair();
            this.aesKey = AESEncryptionUtil.generateAESKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        ChatClient client = new ChatClient("localhost", Constants.SERVER_PORT);
        try {
            client.connect();
            client.sendClientPublicRSAKey();
            Thread.sleep(1000);
            client.sendClientAESKey();
            Thread.sleep(2000); // Daj czas na wymianę kluczy
            client.sendMessage("server", "przykladowa wiadomość");
            Thread.sleep(300);
            client.sendMessage("server", "ALA MA KOTA ALE CZY DZIALA ??!!!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void connect() throws Exception {
        this.networkManager = new ClientNetworkManager(new Socket(serverAddress, serverPort));
        this.networkManager.setMessageReceiver(this::handleIncomingMessage);
        new Thread(networkManager).start(); //   pętlę run()  w ClientNetworkManager
        System.out.println("Połączono z serwerem: " + serverAddress + ":" + serverPort);
    }

    public void sendMessage(String recipient, String messageToSend) throws Exception {
        if (!conversationKeys.containsKey(recipient)) {
            //TODO disable send button until the exchange is complete
            System.out.println("No secure session with " + recipient + ". Initiating...");
            pendingMessages.computeIfAbsent(recipient, k -> new LinkedList<>()).add(messageToSend);
            initiateSecureSession(recipient);
            //TODO check if handshake is completed
//            Thread.sleep(1000);
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
    }

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

    public void disconnect() {
        if (networkManager != null) {
            networkManager.close();
            networkManager = null;
        }
        System.out.println("Disconnected from the server.");
    }

    private synchronized void sendClientPublicRSAKey() throws Exception {
        if (rsaKeyPair == null || rsaKeyPair.getPublic() == null) {
            System.err.println("Client public key could not be found.");
            return;
        }
        if (clientPublicKeySent) {
            System.out.println("Client public key already sent");
            return;
        }

        Message wiadomosc_do_wyslania = new Message(
                PUBLIC_KEY_EXCHANGE,
                username,
                "server",
                Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()),
                System.currentTimeMillis()
        );
        networkManager.sendData(wiadomosc_do_wyslania);
        clientPublicKeySent = true;
        System.out.println("Wysłano klucz publiczny RSA klienta.");

    }

    private synchronized void sendClientAESKey() throws Exception {
        if (aesKey == null) {
            System.err.println("Klucz AES jest pusty");
            return;
        }
        if (serverRSAPublicKey == null) {
            System.err.println("Server`s RSA public key not established.");
            return;
        }
        if (clientAESKeySent) {
            System.out.println("Klucz AES was already sent");
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
        System.out.println("Wysłano zaszyfrowany klucz AES.");
        clientAESKeySent = true;
    }

    // Wewnętrzna klasa/interfejs do obsługi odbierania wiadomości od serwera troche to hjest myslace
    private void handleIncomingMessage(Message message) {
        switch (message.getType()) {
            case PUBLIC_KEY_EXCHANGE:
                // Odebranie klucza RSA od serwera
                try {
                    String publicKeyEncoded = message.getPayload();
                    this.serverRSAPublicKey = RSAEncryptionUtil.decodePublicKey(publicKeyEncoded);
                    System.out.println("Odebrano klucz RSA serwera.");
                    // Wysylanie klucza klienta do serwera
                    sendClientPublicRSAKey();
                } catch (Exception e) {
                    System.err.println("Błąd podczas odbierania/dekodowania klucza RSA serwera: " + e.getMessage());
                    e.printStackTrace();
                }
                break;

            case SERVER_INFO:
                System.out.println("SERVER_INFO");
                break;

            case E2E_PUBLIC_KEY_RESPONSE:
                try {
                    JsonObject json = gson.fromJson(message.getPayload(), JsonObject.class);
                    String targetUser = json.get("username").getAsString();
                    String publicKeyString = json.get("publicKey").getAsString();

                    PublicKey userKey = RSAEncryptionUtil.decodePublicKey(publicKeyString);

                    // In a real app, you'd need to know WHO you requested the key for.
                    // You might need to adjust the message format to include the original target.
                    // For now, we'll assume the last initiated session.

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
                    System.err.println("Błąd podczas wysyłania AES Key");
                    e.printStackTrace();
                }
                break;
            default:
                System.out.println("Odebrano wiadomość nieobsługiwanego typu: " + message.getType());
        }

    }

//    public String decryptedPayload(Message message) {
//        if (this.aesKey == null) {
//            System.err.println("Brak klucza AES sesji");
//            return null;
//        }
//        byte[] ivBytes = message.getEncryptedIv();
//        if (ivBytes == null) {
//            System.err.println("Brak wektora IV w wiadomości.");
//            return null;
//        }
//        IvParameterSpec IV = new IvParameterSpec(ivBytes);
//        String decryptedPayload = null;
//        try {
//            decryptedPayload = AESEncryptionUtil.decrypt(message.getPayload(), this.aesKey, IV);
//        } catch (Exception e) {
//            System.err.println("Błąd podczas deszyfrowania wiadomości AES: " + e.getMessage());
//            throw new RuntimeException(e);
//        }
//        return decryptedPayload;
//    }
//

    // Interfejsy dla listenerów (lub osobne pliki)
    public interface MessageReceivedListener {
        void onMessageReceived(String sender, String content);
    }

    //
    public boolean login(String username, String password) throws Exception {
        // Próbuje zalogować użytkownika
        return false;
    }

    public boolean register(String username, String password) throws Exception {
        // Próbuje zarejestrować użytkownika
        return false;
    }


    // Metody do ustawiania listenerów
    public void setMessageReceivedListener(MessageReceivedListener listener) {
        this.messageListener = listener;
    }

    public void setUserListListener(UserListListener listener) {
        this.userListListener = listener;

    }

    public void setConnectionStatusListener(ConnectionStatusListener listener) {
        this.connectionStatusListener = listener;

    }

    public interface UserListListener {
        void onUserListUpdated(Set<User> users);
    }

    //
    public interface ConnectionStatusListener {
        void onConnectionStatusChanged(boolean connected);
    }
}

