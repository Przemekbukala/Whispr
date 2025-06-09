package com.whispr.securechat.client.networking;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.io.BufferedReader;
 import java.io.ObjectInputStream;
 import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
// Importy dla exceptionów
import com.whispr.securechat.common.Message;
//import com.google.gson.Gson; // Przykładowa biblioteka do JSON [cite: 63]

public class ClientNetworkManager implements Runnable {
    public Socket socket;
    public BufferedReader stdin;
    public ObjectInputStream objectIn;
    public ObjectOutputStream objectOut;

    // tu trzeba bedzie zmienic na private!!!!!!!

//    private ObjectOutputStream objectOut;
//    private ObjectInputStream objectIn;

//    private Gson gson; // Instancja Gson do serializacji/deserializacji JSON

    // Callback do ChatClient, gdy wiadomość zostanie odebrana
//    private MessageReceiver messageReceiver;


    public ClientNetworkManager(Socket socket) {
        this.socket = socket;
        try {
            // Najpierw tworzymy ObjectOutputStream i flushujemy go
            this.objectOut = new ObjectOutputStream(socket.getOutputStream());
            this.objectOut.flush();  //opróznia bufor i wysyła wiadomość
            // Potem tworzymy ObjectInputStream
            this.objectIn = new ObjectInputStream(socket.getInputStream());
            // Standardowy input do wczytywania z klawiatury (do testów)
            this.stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }




//    public void setMessageReceiver(MessageReceiver receiver) { /* ... */ }

    public void sendData(Message message) throws Exception {
        // Serializuje obiekt Message do JSON i wysyła przez socket
    }

    @Override
    public void run() {
        // Główna pętla wątku, odczytująca wiadomości od serwera
    }

    public void close() {
        try {
            if (objectIn != null) objectIn.close();
            if (objectOut != null) objectOut.close();
            if (stdin != null) stdin.close();
            if (socket != null) socket.close();
        }catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Interfejs dla odbiorcy wiadomości
//    public interface MessageReceiver {
//        void onMessageReceived(Message message);
//    }
}