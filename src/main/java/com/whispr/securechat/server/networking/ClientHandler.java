package com.whispr.securechat.server.networking;


import java.net.Socket;
import java.io.BufferedReader; // Jeśli używasz BufferedReader/PrintWriter
import java.io.PrintWriter;    // Jeśli używasz BufferedReader/PrintWriter
// Lub
// import java.io.ObjectInputStream; // Jeśli używasz ObjectInputStream/OutputStream
// import java.io.ObjectOutputStream; // Jeśli używasz ObjectInputStream/OutputStream
import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.security.PrivateKey;
// Importy dla exceptionów
import com.whispr.securechat.common.Message;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.database.DatabaseManager;
import com.whispr.securechat.server.ChatServer; // Może potrzebować dostępu do ClientManager

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private ChatServer server; // Referencja do serwera
    private BufferedReader in; // Strumień wejściowy od klienta
    private PrintWriter out;    // Strumień wyjściowy do klienta
    // Lub
    // private ObjectInputStream objectIn;
    // private ObjectOutputStream objectOut;

    private String username;
    private SecretKey aesKey; // Klucz AES dla tej sesji klienta
    private PrivateKey serverRSAPrivateKey; // Prywatny klucz RSA serwera

    // Konstruktor
    public ClientHandler(Socket socket, ChatServer server, PrivateKey serverRSAPrivateKey) { /* ... */ }

    @Override
    public void run() {
        // Główna pętla wątku, odczytująca i przetwarzająca wiadomości od klienta
    }

    public void sendMessage(Message message) throws Exception {
        // Wysyła wiadomość do tego klienta, szyfrując ją jeśli to wiadomość czatu
    }

    public String getUsername() { /* ... */
        return "";
    }
    public void setUsername(String username) { /* ... */ }
    public SecretKey getAesKey() { /* ... */
        return null;
    }
    public void setAesKey(SecretKey aesKey) { /* ... */ }

    private void handleMessage(Message message) throws Exception {
        // Przetwarza odebraną wiadomość w zależności od jej typu
    }

    private void performRsaKeyExchange(Message incomingMessage) throws Exception {
        // Obsługuje wymianę kluczy RSA (np. odebranie klucza publicznego klienta)
    }

    private void performAesKeyExchange(Message incomingMessage) throws Exception {
        // Obsługuje wymianę kluczy AES (zaszyfrowanych RSA)
    }

    private void authenticateUser(Message loginMessage) throws Exception {
        // Obsługuje logowanie/rejestrację
    }
}
