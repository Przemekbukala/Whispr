package com.whispr.securechat.server.networking;


import java.io.IOException;
import java.io.ObjectStreamException;
import java.net.Socket;
//import java.io.BufferedReader; // Jeśli używasz BufferedReader/PrintWriter
//import java.io.PrintWriter;    // Jeśli używasz BufferedReader/PrintWriter
import com.google.gson.Gson;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Base64;

import com.whispr.securechat.common.Constants;
import com.whispr.securechat.common.LoginPayload;
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.MessageType;
import com.whispr.securechat.security.AESEncryptionUtil;
import com.whispr.securechat.security.RSAEncryptionUtil;
import com.whispr.securechat.database.DatabaseManager;
import com.whispr.securechat.server.ChatServer; // Może potrzebować dostępu do ClientManager

import static com.whispr.securechat.security.RSAEncryptionUtil.decryptRSA;
import static com.whispr.securechat.security.RSAEncryptionUtil.isBase64;

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private ChatServer server; // Referencja do serwera
    private ObjectInputStream objectIn;
    private ObjectOutputStream objectOut;
    private static final Gson gson = new Gson();

    private String username;
    private SecretKey aesKey; // Klucz AES dla tej sesji klienta
    private PrivateKey serverRSAPrivateKey; // Prywatny klucz RSA serwera
    private PublicKey clientRSAPublicKey;
    private boolean isAdmin = false;
    // Konstruktor
    public ClientHandler(Socket socket, ChatServer server, PrivateKey serverRSAPrivateKey) throws IOException {
        this.clientSocket = socket;
        this.server = server;
        this.serverRSAPrivateKey = serverRSAPrivateKey;
        this.objectOut = new ObjectOutputStream(clientSocket.getOutputStream());
        this.objectIn = new ObjectInputStream(clientSocket.getInputStream());
    }

    @Override
    public void run() {
        // Główna pętla wątku, odczytująca i przetwarzająca wiadomości od klienta
        try {
            while (true) {
                try {
                    Message message = (Message) objectIn.readObject();
//                    System.out.println(message);
                    if (message != null) {
                        try {
                            handleMessage(message); // Przekieruj do obsługi wiadomości
                        } catch (Exception e) {
                            System.err.println("Error handling message!");
                            break;
                        }
                        System.out.println(message);
                    }
                } catch (IOException e) {
                    System.out.println("Client " + clientSocket.getInetAddress().getHostAddress() + " disconnected or error reading: " + e.getMessage());
                    server.getClientManager().removeClient(clientSocket.getInetAddress().getHostAddress());
//                    server.getClientManager().removeClient(username);
                    break;
                } catch (ClassNotFoundException e) {
                    System.err.println("Received unknown object type from client " + clientSocket.getInetAddress().getHostAddress() + ": " + e.getMessage());
                    break;
                }
            }
        } finally {
            System.err.println("Closing connection for client: " + clientSocket.getInetAddress().getHostAddress());
            try {
                if (objectOut != null) objectOut.close();
                if (objectIn != null) objectIn.close();
            } catch (IOException e) {
                System.err.println("Error closing streams: " + e.getMessage());
            }
            try {
                if (clientSocket != null) clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error closing client socket: " + e.getMessage());
            }
        }
    }
            // szyfruje i wysyła wiadomosc
    public void sendMessage(Message message) throws Exception {
        // Wysyła wiadomość do tego klienta, ktora nie jest zaszyfrowana więc szyfrujemy

        if (!clientSocket.isClosed() && objectOut != null) {
            if (message.getType() == MessageType.CHAT_MESSAGE) {
                IvParameterSpec IV = AESEncryptionUtil.generateIVParameterSpec();
                String contentToEncrypt = message.getPayload();
                String encrypted_data = AESEncryptionUtil.encrypt(contentToEncrypt.getBytes(), this.aesKey, IV);
                message.setPayload(encrypted_data);
                message.setEncryptedIv(IV.getIV());
                message.setTimestamp(System.currentTimeMillis());
            }
            objectOut.writeObject(message);
            objectOut.flush();
        } else {
            System.err.println("Attempted to send a message to a closed socket for user: " + username);
        }

    }

    public String getUsername() { /* ... */
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public SecretKey getAesKey() { /* ... */
        return aesKey;
    }

    public void setAesKey(SecretKey aesKey) {
        this.aesKey = aesKey;
    }


   void sendPublicRSAKey(PublicKey publicKey) {
        try {
            PublicKey serverPublicKey = server.getServerRSAPublicKey();
            String encodedPublicKey =  Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
            Message publicKeyMessage = new Message(
                    MessageType.PUBLIC_KEY_EXCHANGE,
                    "server",
                    username,
                    encodedPublicKey,null,
                    System.currentTimeMillis()
            );
            objectOut.writeObject(publicKeyMessage);
            objectOut.flush();
            System.out.println("Serwer wysłał swój klucz publiczny RSA do " + clientSocket.getInetAddress().getHostAddress());
        } catch (IOException e) {
            System.err.println("Błąd wysyłania klucza publicznego serwera do klienta");
        }
    }

    public String decryptChatMessage(Message message) throws Exception {
        if (this.aesKey == null) {
            throw new IllegalStateException("AES key not established for: " + username);
        }
        IvParameterSpec iv = new IvParameterSpec(message.getEncryptedIv());
        return AESEncryptionUtil.decrypt(message.getPayload(), this.aesKey, iv);
    }



    private void handleMessage(Message message) throws Exception {
        switch (message.getType()) {
            case PUBLIC_KEY_EXCHANGE:
                try {
                    String client_RSA=message.getPayload();
                    this.clientRSAPublicKey = RSAEncryptionUtil.decodePublicKey(client_RSA);
                    System.out.println("Odebrano i zapisano klucz publiczny RSA od klienta: ");
                } catch (Exception e) {
                    System.err.println("Błąd podczas dekodowania klucza publicznego klienta: " + e.getMessage());
                    throw e; // Rzuć wyjątek dalej, aby obsłużyć błąd w pętli run()
                }
                sendPublicRSAKey(server.getServerRSAPublicKey());
                break;
            case LOGIN:
                // Tutaj logika logowania
                handleLogin(message);
                break;
            case REGISTER:
                // Tutaj logika rejestracji
                handleRegistration(message);
                break;
            case CHAT_MESSAGE:
                // Tutaj logika przesyłania wiadomości
                processChatMessage(message);
                break;
            case ADMIN_LOGIN:
                handleAdminLogin(message);
                break;
            // ... inne przypadki
            case AES_KEY_EXCHANGE:
                try {
                    String encryptedAesKeyBase64 = message.getPayload();
                    System.out.println("Payload otrzymany na serwerze: " + message.getPayload());
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
                    System.out.println("Serwer odebrał i odszyfrował klucz AES od klienta: " + username);
                } catch (Exception e) {
                    System.err.println("Błąd podczas przetwarzania wiadomości AES" + e.getMessage());
                    e.printStackTrace();
                }
                break;
            // TU moze dodac waidomosc do klienta ze otryzmal to co chciał
            default:
                // Co zrobić, gdy serwer otrzyma nieznany typ wiadomości?
                System.err.println("Received unknow message type: " + message.getType());
        }
    }


    private void processChatMessage(Message message) {
        try {
            if (aesKey == null) {
                throw new IllegalStateException("Brak klucza AES dla klienta.");
            }
            if (message.getEncryptedIv() == null) {
                throw new IllegalArgumentException("Brak wektora IV w wiadomości.");
            }
            // OdszyfrOWANIE
            IvParameterSpec iv = new IvParameterSpec(message.getEncryptedIv());
            String decryptedMessage = AESEncryptionUtil.decrypt(message.getPayload(), aesKey, iv);
            System.out.println("Odebrano wiadomość od klienta: " + decryptedMessage);
            // WIADOMOSC ktora bedzie fowodrowana
            Message messageToForward = new Message(
                    MessageType.CHAT_MESSAGE,
                    message.getSender(),
                    message.getRecipient(),
                    decryptedMessage,
                    null,
                    System.currentTimeMillis()
            );
            server.getClientManager().forwardMessage(messageToForward);
        } catch (Exception e) {
            System.err.println("Błąd podczas przetwarzania wiadomości CHAT_MESSAGE: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleLogin(Message message) {
        String gsonPayload = message.getPayload();
        LoginPayload loginPayload = gson.fromJson(gsonPayload, LoginPayload.class);

        final String username = loginPayload.getUsername();
        final String password = loginPayload.getPassword();
        IvParameterSpec IV_2 = null;

        String payload_to_encript;
        String encrypted_data;
        try {
            boolean wasLoginSuccessful = server.getDbManager().verifyCredentials(username, password);
            IV_2 = AESEncryptionUtil.generateIVParameterSpec();

            payload_to_encript = null;
            encrypted_data = null;

            if (wasLoginSuccessful) {
                this.username = username;
                server.getClientManager().addClient(username, this);
                payload_to_encript = "Logged successfully!";
                encrypted_data = AESEncryptionUtil.encrypt(payload_to_encript.getBytes(), this.aesKey, IV_2);
                Message loginConfirmationMessage = new Message(MessageType.SERVER_INFO,
                        "server", username, encrypted_data, IV_2.getIV(),
                        System.currentTimeMillis());
                sendMessage(loginConfirmationMessage);
                server.getClientManager().broadcastUserList();
            } else {
                payload_to_encript = "Username or password incorrect!";
                encrypted_data = AESEncryptionUtil.encrypt(payload_to_encript.getBytes(), this.aesKey, IV_2);

                Message loginRejectionMessage = new Message(MessageType.ERROR,
                        "server", username, encrypted_data, IV_2.getIV(),
                        System.currentTimeMillis());
                sendMessage(loginRejectionMessage);
            }
        } catch (Exception e) {
            payload_to_encript = "Server error during login.";
            try {
                encrypted_data = AESEncryptionUtil.encrypt(payload_to_encript.getBytes(), this.aesKey, IV_2);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }

            System.err.println("Error while logging in user: " + username);
            Message loginErrorMessage = new Message(MessageType.ERROR,
                    "server", username, encrypted_data, IV_2.getIV(),
                    System.currentTimeMillis());
            try {
                sendMessage(loginErrorMessage);
            } catch (Exception ex) {
                System.err.println("Failed to send error message: " + ex.getMessage());
            }
            e.printStackTrace();
        }
    }

    private void handleRegistration(Message message) {
        String gsonPayload = message.getPayload();
        LoginPayload registrationPayload = gson.fromJson(gsonPayload, LoginPayload.class);

        final String username = registrationPayload.getUsername();
        final String password = registrationPayload.getPassword();
        IvParameterSpec IV_2 = null;
        try {
             IV_2 = AESEncryptionUtil.generateIVParameterSpec();
            boolean wasRegistrationSuccessful = server.getDbManager().registerUser(username, password);
            if (wasRegistrationSuccessful) {
                String payload_to_encript="Registration successful";
                String encrypted_data = AESEncryptionUtil.encrypt(payload_to_encript.getBytes(), this.aesKey, IV_2);


                Message successfulRegistration = new Message(MessageType.SERVER_INFO,
                        "server", username, encrypted_data,IV_2.getIV(),
                        System.currentTimeMillis());
                sendMessage(successfulRegistration);
            } else {
                String payload_to_encript="User with this name already exists.";
                String encrypted_data = AESEncryptionUtil.encrypt(payload_to_encript.getBytes(), this.aesKey, IV_2);

                Message failureRegistration = new Message(MessageType.ERROR,
                        "server", username, encrypted_data,IV_2.getIV(),
                        System.currentTimeMillis());
                sendMessage(failureRegistration);
            }
        } catch (Exception e) {
            String payload_to_encript="Server error during registration.";
            String encrypted_data=null;
            try {
                 encrypted_data = AESEncryptionUtil.encrypt(payload_to_encript.getBytes(), this.aesKey, IV_2);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }

            System.err.println("Error during user registration: " + username);
            Message registrationErrorMessage = new Message(MessageType.ERROR,
                    "server", username, encrypted_data,IV_2.getIV(),
                    System.currentTimeMillis());
            try {
                sendMessage(registrationErrorMessage);
            } catch (Exception ex) {
                System.err.println("Failed to send error message: " + ex.getMessage());
            }
            e.printStackTrace();
        }
    }

    private void handleAdminLogin(Message message) {
        try {

            byte[] ivBytes = message.getEncryptedIv();
            IvParameterSpec IV = new IvParameterSpec(ivBytes);
            String decodedPayload = AESEncryptionUtil.decrypt(message.getPayload(), this.aesKey, IV);

                IvParameterSpec IV_2 = AESEncryptionUtil.generateIVParameterSpec();
            if (decodedPayload.equals(Constants.ADMIN_PASSWORD)) {
                String payload_to_encript="Authentication successful. Welcome, admin.";
                String encrypted_data = AESEncryptionUtil.encrypt(payload_to_encript.getBytes(), this.aesKey, IV_2);
                this.isAdmin = true;
                System.out.println("Admin authenticated successfully for client: " + clientSocket.getInetAddress());
                Message successMessage = new Message(
                        MessageType.SERVER_INFO,
                        "server",
                        "admin",
                        encrypted_data,IV_2.getIV(),
                        System.currentTimeMillis()
                );
                sendMessage(successMessage);
            } else {

                System.err.println("Failed admin login attempt from: " + clientSocket.getInetAddress());
                Message failureMessage = new Message(
                        MessageType.ERROR,
                        "server",
                        "admin",
                        "Authentication failed. Invalid password.",IV_2.getIV(),
                        System.currentTimeMillis()
                );
                sendMessage(failureMessage);
            }
        } catch (Exception e) {
            System.err.println("Error during admin login process: " + e.getMessage());
        }
    }


    //TODO usnac na 99%
    private void authenticateUser(Message loginMessage) throws Exception {
        // Obsługuje logowanie/rejestrację
    }
}
