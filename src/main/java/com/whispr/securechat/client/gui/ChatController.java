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
//public class ChatController{

public class ChatController implements ChatClient.MessageReceivedListener, ChatClient.UserListListener {
    @FXML
    private ListView<String> chatMessagesListView; // Wyświetla wiadomości
    @FXML
    private TextArea messageInputArea; // Pole do wpisywania wiadomości
    @FXML
    private ListView<User> usersListView; // Lista zalogowanych użytkowników
    @FXML
    private Label welcomeLabel;

    private ChatClient chatClient;
    private ObservableList<User> users;     // Dane dla usersListView
    private Map<String, ObservableList<String>> conversations = new HashMap<>();
    private Set<String> unreadSenders = new HashSet<>();
    private String currentChatUser = null;
    private SceneSwitcher sceneSwitcher;

    public void setChatClient(ChatClient client) {
        this.chatClient = client;
        if (client != null) {
            client.setMessageReceivedListener(this);
            client.setUserListListener(this);

            if (welcomeLabel != null && client.getUsername() != null) {
                welcomeLabel.setText("Witaj, " + client.getUsername());
            }
        }

    }

    @FXML
    private void handleLogoutButtonAction() {
        if (chatClient != null) {
            chatClient.logout();
        }
        // in order to go to login scene
        if (sceneSwitcher != null) {
            sceneSwitcher.switchToLoginScene();
        }
    }

    // interfeace to change scene
    public interface SceneSwitcher {
        void switchToLoginScene();
    }

    public void setSceneSwitcher(SceneSwitcher switcher) {
        this.sceneSwitcher = switcher;
    }

    public interface LoginSuccessHandler {
        public void onLoginSuccess(ChatClient client);
    }

    public void setLoginSuccessHandler(LoginSuccessHandler handler) {
    }

    @FXML
    private void initialize() {
        // Inicjalizacja komponentów GUI i listenerów
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
                    // Jeśli użytkownik jest w zbiorze nieprzeczytanych, pogrub tekst
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

    private void displayConversation(String username) {
        unreadSenders.remove(username);
        usersListView.refresh();

        conversations.putIfAbsent(username, javafx.collections.FXCollections.observableArrayList());
        chatMessagesListView.setItems(conversations.get(username));
    }

    @FXML
    private void handleSendMessageButtonAction() {
        String message = messageInputArea.getText().trim();
        User recipient = usersListView.getSelectionModel().getSelectedItem();
        if (!message.isEmpty() && chatClient != null && recipient != null) {
            try {
                chatClient.sendMessage(recipient.getUsername(), message);

                // Dodaj wysłaną wiadomość do lokalnej historii konwersacji
                ObservableList<String> chatHistory = conversations.get(recipient.getUsername());
                if (chatHistory != null) {
                    chatHistory.add("Me: " + message);
                }

                messageInputArea.clear();
            } catch (Exception e) {
                // Dodaj błąd do aktualnie aktywnego okna czatu
                if (currentChatUser != null) {
                    conversations.get(currentChatUser).add("Error: " + e.getMessage());
                }
            }
        }
    }


    @Override
    public void onMessageReceived(String sender, String content) {
        Platform.runLater(() -> {
            // Jeśli wiadomość nie pochodzi od osoby, z którą aktualnie piszemy
            if (!sender.equals(currentChatUser)) {
                unreadSenders.add(sender);
                usersListView.refresh(); // Ważne: Odśwież listę, aby pokazać zmianę
            }

            conversations.putIfAbsent(sender, javafx.collections.FXCollections.observableArrayList());
            ObservableList<String> chatHistory = conversations.get(sender);
            chatHistory.add(sender + ": " + content);
        });
    }

    @Override
    public void onUserListUpdated(Set<User> updatedUsers) {
        Platform.runLater(() -> {
            users.setAll(updatedUsers); //
        });
    }


    private String getSelectedRecipient() {
        User selected = usersListView.getSelectionModel().getSelectedItem(); //
        if (selected != null) {
            return selected.getUsername(); //
        }
        return null;
    }
}

