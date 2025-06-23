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


/**
 * Manages all active client and admin connections to the server.
 * This class is responsible for tracking logged-in users, broadcasting user list updates,
 * forwarding private messages, and relaying information to administrators.
 * It is designed to be thread-safe.
 */
public class ClientManager {
    private ConcurrentHashMap<String, ClientHandler> loggedInClients;
    private final Map<String, ClientHandler> loggedInAdmins;

    /**
     * Constructs a new ClientManager.
     * Initializes thread-safe collections for clients and admins.
     */
    public ClientManager() {
        loggedInClients = new ConcurrentHashMap<>(MAX_CLIENTS);
        loggedInAdmins = new ConcurrentHashMap<>();
    }

    /**
     * Adds a newly authenticated client to the manager.
     *
     * @param username The username of the client.
     * @param handler  The {@link ClientHandler} instance managing the client's connection.
     */
    public void addClient(String username, ClientHandler handler) {
        loggedInClients.put(username, handler);

    }

    /**
     * Removes a disconnected or logged-out client.
     *
     * @param username The username of the client to remove.
     */
    public void removeClient(String username) {
        loggedInClients.remove(username);
        notifyClientsOfUserListChange();
    }

    /**
     * Forwards a private message from a sender to a recipient.
     * The message is passed to the recipient's {@link ClientHandler} for delivery.
     *
     * @param message The {@link Message} to be forwarded.
     * @throws Exception if the recipient's handler is not found or sending fails.
     */
    public void forwardMessage(Message message) throws Exception {
        // Przekazuje wiadomość do wybranego odbiorcy
        final String recipientUsername = message.getRecipient();
        ClientHandler recipientHandler = loggedInClients.get(recipientUsername);

        if (recipientHandler != null) {
            recipientHandler.sendMessage(message);
        } else {
            System.err.println("Trying to reach non-existing or logged out user: " + recipientUsername);
        }

    }

    /**
     * Broadcasts the current list of online users to all connected clients.
     * The user list is serialized to JSON, encrypted with each client's session key, and sent.
     */
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

    /**
     * Retrieves a set of all currently logged-in users.
     *
     * @return A {@link Set} of {@link User} objects representing online users.
     */
    public Set<User> getLoggedInUsers() {
        Set<User> onlineUsers = new HashSet<>();
        Set<String> usernamesSet = loggedInClients.keySet();
        for (var userEntry : usernamesSet) {
            User user = new User(userEntry, true);
            onlineUsers.add(user);
        }
        return onlineUsers;

    }

    /**
     * Triggers an update of the user list for all connected clients and admins.
     */
    public void notifyClientsOfUserListChange() {
        broadcastUserList();
        notifyUserListChangedForAdmin();
    }

    /**
     * Sends the current list of online users to all connected administrators.
     * This is separate from the regular user broadcast.
     */
    private void notifyUserListChangedForAdmin() {
        Set<User> onlineUsers = getLoggedInUsers();
        String jsonPayload = new Gson().toJson(onlineUsers);

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

    /**
     * Registers an authenticated administrator's connection handler.
     *
     * @param adminUsername The username of the admin.
     * @param adminHandler  The handler for the admin's connection.
     */
    public void addAdmin(String adminUsername, ClientHandler adminHandler) {
        loggedInAdmins.put(adminUsername, adminHandler);
    }

    /**
     * Removes a disconnected or logged-out administrator.
     *
     * @param adminUsername The username of the admin to remove.
     */
    public void removeAdmin(String adminUsername) {
        loggedInAdmins.remove(adminUsername);
    }

    /**
     * Broadcasts a log message to all connected administrators.
     * Useful for real-time monitoring of server events.
     *
     * @param logMessage The log message to be sent.
     */
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

    /**
     * Kicks a user from the server upon an admin's request.
     * Sends a notification to the user and then closes their connection.
     *
     * @param usernameToKick The username of the user to be kicked.
     * @param adminUsername  The username of the admin performing the action.
     */
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