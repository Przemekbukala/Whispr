package com.whispr.securechat.client.gui;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.collections.ObservableList; // Dla ListView
import com.whispr.securechat.client.ChatClient;
import com.whispr.securechat.common.User;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * This class manages the UI for the chat functionality, handling user interactions,
 * displaying chat messages, and showing the list of online users.
 * <p>
 * It implements the MessageReceivedListener and UserListListener interfaces to receive updates from
 * the ChatClient when new messages arrive or when the user list changes.
 * </p>
 */
public class ChatController implements ChatClient.MessageReceivedListener, ChatClient.UserListListener {
    /** ListView that displays chat messages for the currently selected conversation */
    @FXML
    private ListView<String> chatMessagesListView;
    /** Text area where the user can type messages to send */
    @FXML
    private TextArea messageInputArea;
    /** ListView that displays all online users */
    @FXML
    private ListView<User> usersListView;
    /** Label displaying welcome message with the current user's name */
    @FXML
    private Label welcomeLabel;
    /** Reference to the ChatClient that handles communication with the server */
    private ChatClient chatClient;
    /** Observable list of users for binding to the usersListView */
    private ObservableList<User> users;
    /** Map storing chat history for each user conversation */
    private Map<String, ObservableList<String>> conversations = new HashMap<>();
    /** Set of usernames who have sent messages that haven't been read yet */
    private Set<String> unreadSenders = new HashSet<>();
    /** Username of the user whose conversation is currently displayed */
    private String currentChatUser = null;
    /** Reference to the scene switcher for handling navigation between screens */
    private SceneSwitcher sceneSwitcher;

    /**
     * Sets the ChatClient instance for this controller and configures listeners.
     * This method connects the controller to the ChatClient that handles server
     * communication.
     * @param client The ChatClient instance to use for server communication
     */
    public void setChatClient(ChatClient client) {
        this.chatClient = client;
        if (client != null) {
            client.setMessageReceivedListener(this);
            client.setUserListListener(this);

            if (welcomeLabel != null && client.getUsername() != null) {
                welcomeLabel.setText("Welcome, " + client.getUsername());
            }
        }

    }

    /**
     * Handles the logout button click event.
     */
    @FXML
    private void handleLogoutButtonAction() {
        if (chatClient != null) {
            chatClient.logout();
        }
        if (sceneSwitcher != null) {
            sceneSwitcher.switchToLoginScene();
        }
    }

    /**
     * Interface for switching between different scenes in the application.
     * <p>
     * This interface is implemented by the MainApplication to allow the ChatController
     * to request navigation back to the login screen when the user logs out.
     */
    public interface SceneSwitcher {
        /**
         * Switches the application view to the login scene.
         */
        void switchToLoginScene();
    }

    /**
     * Sets the SceneSwitcher implementation for this controller.
     * <p>
     * This method allows the MainApplication to provide a way for the controller
     * to navigate between screens when needed.
     *
     * @param switcher The SceneSwitcher implementation to use for navigation
     */
    public void setSceneSwitcher(SceneSwitcher switcher) {
        this.sceneSwitcher = switcher;
    }

    /**
     * Initializes the controller after FXML fields are injected.
     */
    @FXML
    private void initialize() {
        // Initialize GUI components and listeners
        if (users == null) {
            users = javafx.collections.FXCollections.observableArrayList();
        }
        usersListView.setItems(users);

        usersListView.setCellFactory(param -> new ListCell<User>() {
            @Override
            protected void updateItem(User user, boolean empty) {
                super.updateItem(user, empty);

                if (empty || user == null || user.getUsername() == null) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(user.getUsername());
                    if (unreadSenders.contains(user.getUsername())) {
                        setStyle("-fx-font-weight: bold;");
                    } else {
                        setStyle("");
                    }
                }
            }
        });

        usersListView.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                currentChatUser = newSelection.getUsername();
                displayConversation(currentChatUser);
            }
        });
    }

    /**
     * Displays the conversation with the specified user.
     * <p>
     * This method switches the chat message display to show the conversation history
     * with the selected user.
     * @param username The username of the user whose conversation should be displayed
     */
    private void displayConversation(String username) {
        unreadSenders.remove(username);
        usersListView.refresh();

        conversations.putIfAbsent(username, javafx.collections.FXCollections.observableArrayList());
        chatMessagesListView.setItems(conversations.get(username));
    }

    /**
     * This method is called when the user clicks the send button in the message input area.
     * It retrieves the message text and the selected recipient,
     * sends the message to the server via the ChatClient, and updates the local conversation
     * history to display the sent message. If an error occurs during sending, an error
     * message is added to the conversation.
     */
    @FXML
    private void handleSendMessageButtonAction() {
        String message = messageInputArea.getText().trim();
        User recipient = usersListView.getSelectionModel().getSelectedItem();
        if (!message.isEmpty() && chatClient != null && recipient != null) {
            try {
                chatClient.sendMessage(recipient.getUsername(), message);

                ObservableList<String> chatHistory = conversations.get(recipient.getUsername());
                if (chatHistory != null) {
                    chatHistory.add("Me: " + message);
                }

                messageInputArea.clear();
            } catch (Exception e) {
                if (currentChatUser != null) {
                    conversations.get(currentChatUser).add("Error: " + e.getMessage());
                }
            }
        }
    }


    /**
     * Called when a new message is received from another user.
     * <p>
     * It adds the message to the appropriate conversation history and marks the message
     * as unread if the sender's conversation is not currently displayed.
     * @param sender The username of the user who sent the message.
     * @param content The content of the received message.
     */
    @Override
    public void onMessageReceived(String sender, String content) {
        Platform.runLater(() -> {
            if (!sender.equals(currentChatUser)) {
                unreadSenders.add(sender);
                usersListView.refresh();
            }
            conversations.putIfAbsent(sender, javafx.collections.FXCollections.observableArrayList());
            ObservableList<String> chatHistory = conversations.get(sender);
            chatHistory.add(sender + ": " + content);
        });
    }

    /**
     * Called when the list of online users is updated.
     * <p>
     * This method is invoked by the ChatClient when the server sends an updated list of
     * users.
     * @param updatedUsers The updated set of users currently online
     */
    @Override
    public void onUserListUpdated(Set<User> updatedUsers) {
        Platform.runLater(() -> {
            users.setAll(updatedUsers);
        });
    }
}

