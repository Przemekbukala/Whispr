package com.whispr.securechat.client;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Set;
// Importy dla exceptionów
import com.whispr.securechat.client.networking.ClientNetworkManager;
//import com.whispr.securechat.common.Constants;
//import com.whispr.securechat.common.Message;
//import com.whispr.securechat.common.User;
//import com.whispr.securechat.security.AESEncryptionUtil;
//import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.common.Constants;
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.User;
import com.whispr.securechat.server.ChatServer;

import static com.whispr.securechat.common.MessageType.CHAT_MESSAGE;
//  trzeba załątwic juz pełną komunikacje RSA wymiana rzeczy itp niehc to ładnie smiga i wgl
// fajna komunikacja serwer- klient porządna tak aby na koncu tylko zosatła zrobienei frontu!!!!!!!!!!!






public class ChatClient {
    private String serverAddress;
    private int serverPort;
    private ClientNetworkManager networkManager;
    private String username;
//    private SecretKey aesKey; // Klucz AES dla sesji klienta
//    private KeyPair rsaKeyPair; // Para kluczy RSA klienta
//    private PublicKey serverRSAPublicKey; // Klucz publiczny RSA serwera
    // Callbacki dla GUI (lub event bus)
//    private MessageReceivedListener messageListener;
//    private UserListListener userListListener;
    private ConnectionStatusListener connectionStatusListener;

    public ChatClient(String serverAddress, int serverPort) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.networkManager=null;
    }

    public static void main(String[] args) {
        ChatClient client = new ChatClient("localhost", Constants.SERVER_PORT);
        try {
            client.connect();
            client.sendMessage("server","przykladowa wiadomość");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void connect() throws Exception {
        Socket socket = new Socket(serverAddress, serverPort);
        System.out.println("Połączono z serwerem: " + serverAddress + ":" + serverPort);
        this.networkManager=new ClientNetworkManager(socket);
    }

    public void sendMessage(String recipient, String content) throws Exception {
        // Szyfruje i wysyła wiadomość do serwera
        Message wiadomosc_do_wyslania = new Message(
                CHAT_MESSAGE,
                username,
                recipient,
                content,
                System.currentTimeMillis()
        );
        // Wątek wysyłający wiadomości do serwera
        new Thread(() -> {
            try {
                while ( true) {
                    networkManager.objectOut.writeObject(wiadomosc_do_wyslania);
                    networkManager.objectOut.flush();
                    System.out.println("Klient: " + wiadomosc_do_wyslania);

                    //sprawdzenie wyywołania disconnect
                    disconnect();
                    break;
                }
            } catch (IOException e) {
                System.out.println("Błąd wysyłania wiadomości.");
            }
        }).start();
    }

    public void disconnect() {
            if (networkManager != null) {
                networkManager.close();
                networkManager = null;
            }
            System.out.println("Disconnected from the server.");
    }

    public boolean login(String username, String password) throws Exception {
        // Próbuje zalogować użytkownika
        return false;
    }

    public boolean register(String username, String password) throws Exception {
        // Próbuje zarejestrować użytkownika
        return false;
    }


//    // Metody do ustawiania listenerów
//    public void setMessageReceivedListener(MessageReceivedListener listener) { /* ... */ }
//    public void setUserListListener(UserListListener listener) { /* ... */ }


//    public void setConnectionStatusListener(ConnectionStatusListener listener) {
//        this.connectionStatusListener = listener;
//
//    }

    //    // Wewnętrzna klasa/interfejs do obsługi odbierania wiadomości od serwera
//    private void handleIncomingMessage(Message message) {
//        // Przetwarza odebraną wiadomość i przekazuje do GUI
//    }
//
//    private void initializeKeyExchange() throws Exception {
//        // Rozpoczyna proces wymiany kluczy RSA/AES z serwerem [cite: 55]
//    }
//
//    // Interfejsy dla listenerów (lub osobne pliki)
    public interface MessageReceivedListener {
                void onMessageReceived(String sender, String content);
    }
//
        public interface UserListListener {
        void onUserListUpdated(Set<User> users);
        }

        public interface ConnectionStatusListener {
        void onConnectionStatusChanged(boolean connected);
        }
    }

