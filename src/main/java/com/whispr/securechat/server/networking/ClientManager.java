package com.whispr.securechat.server.networking;


import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Set;
// Importy dla Message i User
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.User;

public class ClientManager {
    // Mapuje login użytkownika na jego ClientHandler
    private Map<String, ClientHandler> loggedInClients;

    public ClientManager() { /* ... */ } // Konstruktor inicjalizujący mapę

    public void addClient(String username, ClientHandler handler) {
        // Dodaje nowego zalogowanego klienta
    }

    public void removeClient(String username) {
        // Usuwa klienta po wylogowaniu/rozłączeniu
    }

    public ClientHandler getClientHandler(String username) {
        // Zwraca handler dla danego użytkownika
        return null;
    }

    public void forwardMessage(Message message) throws Exception {
        // Przekazuje wiadomość do wybranego odbiorcy
    }

    public void broadcastUserList() {
        // Wysyła aktualną listę użytkowników do wszystkich zalogowanych klientów
    }

    public Set<User> getLoggedInUsers() {
        // Zwraca listę aktualnie zalogowanych użytkowników
        return null;
    }
}