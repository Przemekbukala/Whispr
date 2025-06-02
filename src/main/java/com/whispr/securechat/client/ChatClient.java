package com.whispr.securechat.client;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
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
import com.whispr.securechat.server.ChatServer;

public class ChatClient {
    private String serverAddress;
    private int serverPort;
    private ClientNetworkManager networkManager;
//    private String username;
//    private SecretKey aesKey; // Klucz AES dla sesji klienta
//    private KeyPair rsaKeyPair; // Para kluczy RSA klienta
//    private PublicKey serverRSAPublicKey; // Klucz publiczny RSA serwera
    // Callbacki dla GUI (lub event bus)
//    private MessageReceivedListener messageListener;
//    private UserListListener userListListener;
//    private ConnectionStatusListener connectionStatusListener;

    public ChatClient(String serverAddress, int serverPort) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        try (Socket s = new Socket(this.serverAddress, this.serverPort);)
        {
            networkManager=new ClientNetworkManager(s);
            String outs;
            String ins;
            while ((outs = networkManager.in.readLine()) != null) {

                System.out.println("Serwer:␣" + outs);
                ins = networkManager.stdin.readLine();
                if (ins != null) {
                    System.out.println("Klient:␣" + ins);
                    networkManager.out.println(ins);
                }
            }
        } catch (Exception e) {
            System.out.println("NIeprawidłowe połączonie!!!!");
            e.printStackTrace(); // <-- dodaj to

        }
    }

    public static void main(String[] args) {
        ChatClient client = new ChatClient("localhost", 5001);
    }

    public void connect() throws Exception {
        // Nawiązuje połączenie z serwerem [cite: 53]
    }

    public void disconnect() {
        // Rozłącza się z serwerem
    }

    public boolean login(String username, String password) throws Exception {
        // Próbuje zalogować użytkownika
        return false;
    }

    public boolean register(String username, String password) throws Exception {
        // Próbuje zarejestrować użytkownika
        return false;
    }

    public void sendMessage(String recipient, String content) throws Exception {
        // Szyfruje i wysyła wiadomość do serwera
    }

//    // Metody do ustawiania listenerów
//    public void setMessageReceivedListener(MessageReceivedListener listener) { /* ... */ }
//    public void setUserListListener(UserListListener listener) { /* ... */ }
//    public void setConnectionStatusListener(ConnectionStatusListener listener) { /* ... */ }

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
        //        void onMessageReceived(String sender, String content);
//    }
//
        public interface UserListListener {
//        void onUserListUpdated(Set<User> users);
        }

        public interface ConnectionStatusListener {
//        void onConnectionStatusChanged(boolean connected);
        }
    }
}