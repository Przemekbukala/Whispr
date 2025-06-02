package com.whispr.securechat.server;
import com.whispr.securechat.common.Constants;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
// Do zarządzania pulą wątków
//import com.whispr.securechat.common.Constants;
//// Importy dla exceptionów
//import com.whispr.securechat.database.DatabaseManager;
//import com.whispr.securechat.server.networking.ClientManager;

public class ChatServer {
    private int port;
    private ServerSocket serverSocket;
//    private ExecutorService clientThreadPool; // Pula wątków dla ClientHandlerów
//    private DatabaseManager dbManager;
//    private ClientManager clientManager; // Do zarządzania połączonymi klientami

    public ChatServer(int port) {
        try(ServerSocket ss = new ServerSocket(port);
            Socket cs = ss.accept();
            PrintWriter out =
                    new PrintWriter(cs.getOutputStream(), true);
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(cs.getInputStream()));
            ){
        String outl = "Napisz␣cos␣[’q’␣konczy]";
        out.println(outl);
        String inl;
        while ( (inl = in.readLine()) != null ) {
            if( inl.equals("q") ) break;
            out.println(outl);
        }
        out.close(); in.close();
        cs.close(); ss.close();
    } catch (Exception e) {
            System.out.println("Problem z połączeniem ");
        }

    }
    public  static void main(String[] args) {
    ChatServer obj=  new  ChatServer(5001);
    }
    public void start() throws Exception {
        // Uruchamia ServerSocket i czeka na połączenia klientów [cite: 53]
    }

    public void stop() {
        // Zatrzymuje serwer i zamyka wszystkie połączenia
    }

//    // Metody pomocnicze (np. do obsługi logiki serwera przekazywanej z ClientHandler)
//    public ClientManager getClientManager() { /* ... */
//        return null;
//    }
//    public DatabaseManager getDbManager() { /* ... */
//        return null;
//    }
}
