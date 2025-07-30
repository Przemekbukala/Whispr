package com.whispr.securechat.admin;

import com.whispr.securechat.common.User;

import java.util.Set;

/**
 * Interface for receiving notifications and updates from the AdminClient.
 * <p>
 * This interface defines callback methods that are triggered when specific events occur
 * in the AdminClient, such as when the secure session is established, login responses
 * are received, or when updates to the user list or log messages are available.
 * <p>
 * Implementations of this interface should handle these events appropriately, typically
 * by updating the UI or performing other actions in response to admin client events.
 */
public interface AdminClientListener {
    /**
     * Called when the secure session between the admin client and server is established.
     * <p>
     * This method is invoked after the encryption keys have been successfully exchanged
     * and the secure communication channel is ready for use. At this point, the admin
     * can proceed with login or other secure operations.
     */
    void onSessionReady();
    /**
     * Called when a response to an admin login attempt is received from the server.
     * <p>
     * This method is invoked after the admin client attempts to authenticate with the server.
     * It provides information about whether the login was successful and includes any
     * relevant message from the server.
     * @param success True if the login was successful, false otherwise
     * @param message A message from the server describing the result of the login attempt
     */
    void onLoginResponse(boolean success, String message);
    /**
     * Called when the server sends an updated list of users.
     * <p>
     * This method is invoked whenever there are changes to the user list on the server,
     * such as when users log in, log out, or are kicked. The provided set contains
     * information about all current users, including their online status.
     *
     * @param users A set of User objects representing all users currently in the system.
     */
    void onUserListUpdated(Set<User> users);
    /**
     * Called when the server sends a new log message to the admin client.
     * <p>
     * This method is invoked when significant events occur on the server that
     * administrators should be aware of, such as login attempts or system notifications.
     * These messages are displayed in an admin console.
     * @param logMessage The log message text from the server
     */
    void onNewLogMessage(String logMessage);
}
