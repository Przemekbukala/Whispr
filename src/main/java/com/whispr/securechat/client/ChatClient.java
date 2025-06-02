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
        this.networkManager=null;
//        try (Socket s = new Socket(this.serverAddress, this.serverPort);)
//        {
//            networkManager=new ClientNetworkManager(s);
//            String outs;
//            String ins;
//            while ((outs = networkManager.in.readLine()) != null) {
//
//                System.out.println("Serwer:␣" + outs);
//                ins = networkManager.stdin.readLine();
//                if (ins != null) {
//                    System.out.println("Klient:␣" + ins);
//                    networkManager.out.println(ins);
//                }
//            }
//        } catch (Exception e) {
//            System.out.println("NIeprawidłowe połączonie!!!!");
//            e.printStackTrace(); // <-- dodaj to
//
//        }
    }

    public static void main(String[] args) {
        ChatClient client = new ChatClient("localhost", Constants.SERVER_PORT);
        try {
            client.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void connect() throws Exception {
        Socket socket = new Socket(serverAddress, serverPort);
        System.out.println("Połączono z serwerem: " + serverAddress + ":" + serverPort);
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream  ois = new ObjectInputStream(socket.getInputStream());
        BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

        Message wiadomosc_do_wyslania = new Message(
                CHAT_MESSAGE,
                "uzytkownik1",
                "server",
                "Test działania serwera",
                System.currentTimeMillis()
        );

        new Thread(() -> {
            try {
                while (true) {
                    Object obj = ois.readObject();
                    if (obj instanceof Message) {
                        Message msg = (Message) obj;
                        System.out.println("Serwer: " + msg.getPayload());
                    } else {
                        System.out.println("Otrzymano nieznany obiekt: " + obj);
                    }
                }
            } catch (Exception e) {
                System.out.println("Rozłączono z serwerem.");
                // e.printStackTrace();
            }
        }).start();

        // Wątek wysyłający wiadomości do serwera
        new Thread(() -> {
            try {
//                String line;
//                (line = consoleReader.readLine()) != null
                while ( true) {
//                    Message msg = new Message(line);
                    oos.writeObject(wiadomosc_do_wyslania);
                    oos.flush();
                    System.out.println("Klient: " + wiadomosc_do_wyslania);
                    break;
                }
            } catch (IOException e) {
                System.out.println("Błąd wysyłania wiadomości.");
                // e.printStackTrace();
            }
        }).start();
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

