package com.whispr.securechat.client.networking;

import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.io.BufferedReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;

import com.whispr.securechat.common.Message;
//import com.google.gson.Gson; // Przykładowa biblioteka do JSON [cite: 63]

public class ClientNetworkManager implements Runnable {
    public Socket socket;
    public BufferedReader stdin;
    private ObjectOutputStream objectOut;
    private ObjectInputStream objectIn;

//    private Gson gson; // Instancja Gson do serializacji/deserializacji JSON

    // Callback do ChatClient, gdy wiadomość zostanie odebrana
    private MessageReceiver messageReceiver;


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
    public void setMessageReceiver(MessageReceiver receiver) {
        this.messageReceiver = receiver;
    }

    public void sendData(Message message) throws Exception {
        // Serializuje obiekt Message do JSON i wysyła przez socket
        new Thread(() -> {
            try {
                while ( true) {
                    objectOut.writeObject(message);
                    objectOut.flush();
                    System.out.println("Klient: " + message);
                    //sprawdzenie wyywołania disconnect
                    close();
                    break;
                }
            } catch (IOException e) {
                System.out.println("Błąd wysyłania wiadomości.");
            }
        }).start();

    }
    @Override
    public void run() {
        // Główna pętla wątku, odczytująca wiadomości od serwera
        try {
            while (!socket.isClosed()) {
                // Odczyt obiektu typu Message
                Object obj = objectIn.readObject();
                if (obj instanceof Message message) {
                    System.out.println("Odebrano wiadomość od " + message.getSender() + ": " + message.getPayload());
                    messageReceiver.onMessageReceived(message);

                    // W przyszłosci tutaj trzeba dodać  przekazanie do GUI lub listenera.

                } else {
                    System.err.println("Odebrano obiekt nie będący Message: " + obj.getClass());
                }
            }
        } catch (IOException e) {
            System.err.println("Połączenie z serwerem zostało przerwane.");
        } catch (ClassNotFoundException e) {
            System.err.println("Nieznana klasa obiektu odebranego z serwera.");
        } finally {
            // zamyka zasoby po zakończeniu połaczenia
            close();
        }
    }

    public void close() {
        try {
            if (objectIn != null) objectIn.close();
            if (objectOut != null) objectOut.close();
            if (stdin != null) stdin.close();
            if (socket != null) socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

//     Interfejs dla odbiorcy wiadomości
    public interface MessageReceiver {
        void onMessageReceived(Message message);
    }
}