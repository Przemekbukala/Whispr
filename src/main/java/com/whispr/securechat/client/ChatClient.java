package com.whispr.securechat.client;

import javax.crypto.SecretKey;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Set;
// Importy dla exceptionów
import com.whispr.securechat.client.networking.ClientNetworkManager;
import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.common.Constants;
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.User;

import static com.whispr.securechat.common.MessageType.CHAT_MESSAGE;
import static com.whispr.securechat.common.MessageType.PUBLIC_KEY_EXCHANGE;
//  trzeba załątwic juz pełną komunikacje RSA wymiana rzeczy itp niehc to ładnie smiga i wgl
// fajna komunikacja serwer- klient porządna tak aby na koncu tylko zosatła zrobienei frontu!!!!!!!!!!!



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

    public ChatClient(String serverAddress, int serverPort) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.networkManager=null;
        try {
            this.rsaKeyPair=RSAEncryptionUtil.generateRSAKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        ChatClient client = new ChatClient("localhost", Constants.SERVER_PORT);
        try {
            /// Sprawdzenie czy RSA -> null

            System.out.println("\n"+(client.serverRSAPublicKey!=null?client.serverRSAPublicKey.getEncoded():null)+"\n");
            client.connect();
            // Time to  key exchange to complete before attempting to send messages
            client.sendClientPublicKey();
            Thread.sleep(300);
            client.sendMessage("server","przykladowa wiadomość");


            /// Sprawdzenie czy otrzymaliśmy RSA
            client.disconnect();
            System.out.println("\n"+(client.serverRSAPublicKey!=null?client.serverRSAPublicKey.getEncoded():null)+"\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void connect() throws Exception {
        this.networkManager=new ClientNetworkManager(new Socket(serverAddress, serverPort));
        this.networkManager.setMessageReceiver(this::handleIncomingMessage);
        //analgoiczne to tego poniżej
//        networkManager.setMessageReceiver(new ClientNetworkManager.MessageReceiver() {
//            public void onMessageReceived(Message message) {
//                handleIncomingMessage(message);
//            }
//        });
//
        new Thread(networkManager).start(); //   pętlę run()  w ClientNetworkManager
        System.out.println("Połączono z serwerem: " + serverAddress + ":" + serverPort);
    }

    public void sendMessage(String recipient, String content) throws Exception {
        if (serverRSAPublicKey == null) {
            System.err.println("Server`s RSA public key not established.");
            return;
        }
        // Szyfruje i wysyła wiadomość do serwera
        Message wiadomosc_do_wyslania = new Message(
                CHAT_MESSAGE,
                username,
                recipient,
                content,
                System.currentTimeMillis()
        );
        // Wątek wysyłający wiadomości do serwera
        networkManager.sendData(wiadomosc_do_wyslania);
    }

    public void disconnect() {
            if (networkManager != null) {
                networkManager.close();
                networkManager = null;
            }
            System.out.println("Disconnected from the server.");
    }
    //////////////////////
    private void initializeKeyExchange() throws Exception {
//        // Rozpoczyna proces wymiany kluczy RSA/AES z serwerem [cite: 55]

    }

// raczej nie static
//private static void sendClientPublicKey()  throws Exception {
    private synchronized void sendClientPublicKey()  throws Exception {
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
                RSAEncryptionUtil.encodeToString(rsaKeyPair.getPublic().getEncoded()),
                System.currentTimeMillis()
        );
        networkManager.sendData(wiadomosc_do_wyslania);
        clientPublicKeySent = true;
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
                    sendClientPublicKey();

                } catch (Exception e) {
                    System.err.println("Błąd podczas odbierania/dekodowania klucza RSA serwera: " + e.getMessage());
                    e.printStackTrace();
                }
                break;
            case CHAT_MESSAGE:
                String payload = message.getPayload();
                System.out.println("wiadomość od serwera: "+payload);

        // trzeba dodac AES key itd
                if (messageListener != null) {
                    messageListener.onMessageReceived(message.getSender(), message.getPayload());
                }
                break;
            default:
                System.out.println("Odebrano wiadomość nieobsługiwanego typu: " + message.getType());
        }

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

