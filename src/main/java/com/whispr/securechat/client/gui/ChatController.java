package com.whispr.securechat.client.gui;

import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.collections.ObservableList; // Dla ListView
import com.whispr.securechat.client.ChatClient;
import com.whispr.securechat.common.User;

import java.util.Set;

public class ChatController implements ChatClient.MessageReceivedListener, ChatClient.UserListListener {
    @FXML
    private ListView<String> chatMessagesListView; // Wyświetla wiadomości
    @FXML
    private TextArea messageInputArea; // Pole do wpisywania wiadomości
    @FXML
    private ListView<User> usersListView; // Lista zalogowanych użytkowników

    private ChatClient chatClient;
    private ObservableList<String> messages; // Dane dla chatMessagesListView
    private ObservableList<User> users;     // Dane dla usersListView

    public void setChatClient(ChatClient client) { /* ... */ }

    @FXML
    private void initialize() {
        // Inicjalizacja komponentów GUI i listenerów
    }

    @FXML
    private void handleSendMessageButtonAction() {
        // Logika wysyłania wiadomości
    }

    @Override
    public void onMessageReceived(String sender, String content) {
        // Wyświetla nową wiadomość w chatMessagesListView
    }
//
    @Override
    public void onUserListUpdated(Set<User> updatedUsers) {
        // Aktualizuje listę użytkowników w usersListView
    }

    private String getSelectedRecipient() {
        // Zwraca wybranego odbiorcę z listy użytkowników (jeśli wiadomość prywatna)
        return null;
    }
}
