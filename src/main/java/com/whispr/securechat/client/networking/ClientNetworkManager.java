package com.whispr.securechat.client.networking;

import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.io.BufferedReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;

import com.whispr.securechat.common.Message;

import static com.whispr.securechat.common.MessageType.CHAT_MESSAGE;
//import com.google.gson.Gson; // Przykładowa biblioteka do JSON [cite: 63]

public class ClientNetworkManager implements Runnable {
        public Socket socket;
        public BufferedReader stdin;
        private ObjectOutputStream objectOut;
        private ObjectInputStream objectIn;

    //    private Gson gson; // Instancja Gson do serializacji/deserializacji JSON

        // Callback do ChatClient, gdy wiadomość zostanie odebrana
        private MessageReceiver messageReceiver;
        private ConnectionStatusNotifier statusNotifier;


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

        public synchronized void  sendData(Message message) throws Exception {
            // Serializuje obiekt Message do JSON i wysyła przez socket
                        objectOut.writeObject(message);
                        objectOut.flush();
                        System.out.println("Klient: " + message);
        }
        @Override
        public void run() {
            // Główna pętla wątku, odczytująca wiadomości od serwera
            try {
                while (!socket.isClosed()) {
                    // Odczyt obiektu typu Message
                    Object obj = objectIn.readObject();
                    if (obj instanceof Message message) {
                        //tymczasowe roziwazanie wyswietlania w konsoli wiadomosci

                        if(message.getType()==CHAT_MESSAGE){
                            System.out.println(message);
                        }else {
                            System.out.println("Message was received from " + message.getSender() + ": "+" message type: "+message.getType());
                        }
                        if (messageReceiver != null) {
                            messageReceiver.onMessageReceived(message);
                        } else {
                            System.err.println("No message recipient set (messageReceiver == null)");
                        }

                        // W przyszłosci tutaj trzeba dodać  przekazanie do GUI lub listenera.

                    } else {
                        System.err.println("A non-Message object was received: " + obj.getClass());
                    }
                }
            } catch (IOException e) {
                System.err.println("The connection to the server was interrupted.");
                if (statusNotifier != null) {
                    statusNotifier.onConnectionLost();
                }

            } catch (ClassNotFoundException e) {
                System.err.println("Unknown class of object received from server.");
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
         public void setConnectionStatusNotifier(ConnectionStatusNotifier notifier) {
        this.statusNotifier = notifier;
        }

    //     Interfejs dla odbiorcy wiadomości
        public interface MessageReceiver {
            void onMessageReceived(Message message);
        }

        // new interface made in order to give notification to ChatClient
        public interface ConnectionStatusNotifier {
            void onConnectionLost();
        }


}