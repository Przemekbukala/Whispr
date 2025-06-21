package com.whispr.securechat.server.networking;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import com.google.gson.Gson;
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.MessageType;
import com.whispr.securechat.common.User;
import com.whispr.securechat.security.AESEncryptionUtil;

import javax.crypto.spec.IvParameterSpec;

import static com.whispr.securechat.common.Constants.MAX_CLIENTS;

public class ClientManager {
    // Mapuje login użytkownika na jego ClientHandler
    private ConcurrentHashMap<String, ClientHandler> loggedInClients;
    private final Map<String, ClientHandler> loggedInAdmins;

    public ClientManager() {
        loggedInClients = new ConcurrentHashMap<>(MAX_CLIENTS);
        loggedInAdmins = new ConcurrentHashMap<>();
    }

    public void addClient(String username, ClientHandler handler) {
        loggedInClients.put(username, handler);

    }
    public void notifyClientsOfUserListChange() {
        broadcastUserList();
        notifyUserListChangedForAdmin();
    }

    public void removeClient(String username) {
        // Usuwa klienta po wylogowaniu/rozłączeniu
        loggedInClients.remove(username);
        notifyClientsOfUserListChange();
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
        Set<User> onlineUsers = getLoggedInUsers();
        Gson gson = new Gson();
        String jsonPayload = gson.toJson(onlineUsers);

        for (ClientHandler handler : loggedInClients.values()) {
            try {
                IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                String encryptedPayload = AESEncryptionUtil.encrypt(jsonPayload.getBytes(), handler.getAesKey(), iv);

                Message userListMessage = new Message(
                        MessageType.USER_LIST_UPDATE,
                        "server",
                        handler.getUsername(),
                        encryptedPayload,
                        iv.getIV(),
                        System.currentTimeMillis()
                );
                handler.sendMessage(userListMessage);
            } catch (Exception e) {
                System.err.println("Error sending encrypted user list to " + handler.getUsername() + ": " + e.getMessage());
            }
        }
    }

    public Set<User> getLoggedInUsers() {
        Set<User> onlineUsers = new HashSet<>();
        Set<String> usernamesSet = loggedInClients.keySet();
        for (var userEntry : usernamesSet){
            User user = new User(userEntry,true);
            onlineUsers.add(user);
        }
        return onlineUsers;

    }

    private void notifyUserListChangedForAdmin() {
        // Pobieramy listę, której potrzebujemy
        Set<User> onlineUsers = getLoggedInUsers();
        String jsonPayload = new Gson().toJson(onlineUsers);

        // Iterujemy po adminach i wysyłamy aktualizacje (ta część jest poprawna i zostaje)
        for (ClientHandler adminHandler : loggedInAdmins.values()) {
            try {
                IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                String encryptedPayload = AESEncryptionUtil.encrypt(jsonPayload.getBytes(), adminHandler.getAesKey(), iv);

                Message userListMessage = new Message(
                        MessageType.ADMIN_USER_LIST_UPDATE,
                        "server",
                        adminHandler.getUsername(),
                        encryptedPayload,
                        iv.getIV(),
                        System.currentTimeMillis()
                );
                adminHandler.sendMessage(userListMessage);
            } catch (Exception e) {
                System.err.println("Failed to send user list update to admin: " + adminHandler.getUsername());
                e.printStackTrace();
            }
        }
    }

    public void addAdmin(String adminUsername, ClientHandler adminHandler){
        loggedInAdmins.put(adminUsername,adminHandler);
    }
    public void removeAdmin(String adminUsername){
        loggedInAdmins.remove(adminUsername);
    }

    public void broadcastLogToAdmins(String logMessage) {
        for (ClientHandler adminHandler : loggedInAdmins.values()) {
            try {
                IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                String encryptedPayload = AESEncryptionUtil.encrypt(logMessage.getBytes(), adminHandler.getAesKey(), iv);

                Message logRelayMessage = new Message(
                        MessageType.ADMIN_LOG_MESSAGE,
                        "server-log",
                        adminHandler.getUsername(),
                        encryptedPayload,
                        iv.getIV(),
                        System.currentTimeMillis()
                );
                adminHandler.sendMessage(logRelayMessage);
            } catch (Exception e) {
                System.err.println("Failed to send log message to admin: " + adminHandler.getUsername());
                e.printStackTrace();
            }
        }
    }

    public void kickUser(String usernameToKick, String adminUsername) {
        ClientHandler handlerToKick = loggedInClients.get(usernameToKick);
        if (handlerToKick != null) {
            try {
                String kickNote = "You have been kicked from the server by an administrator.";
                IvParameterSpec iv = AESEncryptionUtil.generateIVParameterSpec();
                String encryptedNotice = AESEncryptionUtil.encrypt(kickNote.getBytes(), handlerToKick.getAesKey(), iv);
                Message noticeMessage = new Message(
                        MessageType.ADMIN_KICK_NOTIFICATION,
                        "server",
                        usernameToKick,
                        encryptedNotice,
                        iv.getIV(),
                        System.currentTimeMillis());
                handlerToKick.sendMessage(noticeMessage);
                Thread.sleep(2000);
                handlerToKick.getClientSocket().close();
                broadcastLogToAdmins("User '" + usernameToKick + "' was kicked by admin.");
            } catch (Exception e) {
                System.err.println("Exception while kicking user " + usernameToKick + ": " + e.getMessage());
            }
        } else {
            broadcastLogToAdmins("Admin '" + adminUsername + "' failed to kick user '" + usernameToKick + "': user not found.");
        }
    }
}