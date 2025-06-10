package com.whispr.securechat.server.networking;


import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Set;
// Importy dla Message i User
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.User;

import static com.whispr.securechat.common.Constants.MAX_CLIENTS;

public class ClientManager {
    // Mapuje login użytkownika na jego ClientHandler
    private ConcurrentHashMap<String, ClientHandler> loggedInClients;

    public ClientManager() {
        loggedInClients = new ConcurrentHashMap<>(MAX_CLIENTS);
    } // Konstruktor inicjalizujący mapę

    public void addClient(String username, ClientHandler handler) {
        // Dodaje nowego zalogowanego klienta
        loggedInClients.put(username, handler);
    }

    public void removeClient(String username) {
        // Usuwa klienta po wylogowaniu/rozłączeniu
        loggedInClients.remove(username);
    }

    public ClientHandler getClientHandler(String username) throws IllegalArgumentException {
        ClientHandler handler = loggedInClients.get(username);
        if (handler == null) {
            throw new IllegalArgumentException("No ClientHandler found for username: " + username);
        }
        return handler;
    }

    public void forwardMessage(Message message) throws Exception {
        // Przekazuje wiadomość do wybranego odbiorcy
        final String recipientUsername = message.getRecipient();
        ClientHandler recipientHandler = loggedInClients.get(recipientUsername);

        if (recipientHandler != null) {
            recipientHandler.sendMessage(message);
        } else {
            System.err.println("Trying to reach non-existing or logged out user: " +recipientUsername);

        }

    }

    public void broadcastUserList() {
        // Wysyła aktualną listę użytkowników do wszystkich zalogowanych klientów
    }

    public Set<User> getLoggedInUsers() {
        // Zwraca listę aktualnie zalogowanych użytkowników
        return null;
    }
}