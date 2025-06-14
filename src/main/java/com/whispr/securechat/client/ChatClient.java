package com.whispr.securechat.client;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Set;
// Importy dla exceptionów
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

    public ChatClient(String serverAddress, int serverPort) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.networkManager=null;

        try {
            this.rsaKeyPair=RSAEncryptionUtil.generateRSAKeyPair();
            this.aesKey=AESEncryptionUtil.generateAESKey();
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
            client.sendMessage("server","przykladowa wiadomość");
            Thread.sleep(300);
            client.sendMessage("server","ALA MA KOTA ALE CZY DZIALA ??!!!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void connect() throws Exception {
        this.networkManager=new ClientNetworkManager(new Socket(serverAddress, serverPort));
        this.networkManager.setMessageReceiver(this::handleIncomingMessage);
        new Thread(networkManager).start(); //   pętlę run()  w ClientNetworkManager
        System.out.println("Połączono z serwerem: " + serverAddress + ":" + serverPort);
    }

    public void sendMessage(String recipient, String content_to_send) throws Exception {
        if (serverRSAPublicKey == null) {
            System.err.println("Server`s RSA public key not established.");
            return;
        }
        IvParameterSpec IV = AESEncryptionUtil.generateIVParameterSpec();
        String encrypted_data = AESEncryptionUtil.encrypt(content_to_send.getBytes(), this.aesKey, IV);
        // Szyfruje i wysyła wiadomość do serwera
        Message wiadomosc_do_wyslania = new Message(
                CHAT_MESSAGE,
                username,
                recipient,
                encrypted_data,IV.getIV(),
                System.currentTimeMillis()
        );
        // Wątek wysyłający wiadomości do serwera
        networkManager.sendData(wiadomosc_do_wyslania);
        System.out.println("Wysłano wiadomość: " + content_to_send);
    }

    public void disconnect() {
            if (networkManager != null) {
                networkManager.close();
                networkManager = null;
            }
            System.out.println("Disconnected from the server.");
    }
    private synchronized void sendClientPublicRSAKey()  throws Exception {
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
            case CHAT_MESSAGE:
               String content= decryptedPayload(message);
                System.out.println("Odebrano zaszyfrowaną wiadomość od serwera: " + content);
                if (messageListener != null) {
                    messageListener.onMessageReceived(message.getSender(), message.getPayload());
                }
                break;
            case AES_KEY_EXCHANGE:
                try{
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

    public  String decryptedPayload(Message message)  {
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

