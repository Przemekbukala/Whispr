package com.whispr.securechat.client.networking;


import java.net.Socket;
import java.io.BufferedReader;
import java.io.PrintWriter;
// Lub
// import java.io.ObjectInputStream;
// import java.io.ObjectOutputStream;
// Importy dla exceptionów
import com.whispr.securechat.common.Message;
import com.google.gson.Gson; // Przykładowa biblioteka do JSON [cite: 63]

public class ClientNetworkManager implements Runnable {
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    // Lub
    // private ObjectInputStream objectIn;
    // private ObjectOutputStream objectOut;
    private Gson gson; // Instancja Gson do serializacji/deserializacji JSON

    // Callback do ChatClient, gdy wiadomość zostanie odebrana
    private MessageReceiver messageReceiver;

    public ClientNetworkManager(Socket socket) { /* ... */ }

    public void setMessageReceiver(MessageReceiver receiver) { /* ... */ }

    public void sendData(Message message) throws Exception {
        // Serializuje obiekt Message do JSON i wysyła przez socket
    }

    @Override
    public void run() {
        // Główna pętla wątku, odczytująca wiadomości od serwera
    }

    public void close() {
        // Zamyka socket i strumienie
    }

    // Interfejs dla odbiorcy wiadomości
    public interface MessageReceiver {
        void onMessageReceived(Message message);
    }
}