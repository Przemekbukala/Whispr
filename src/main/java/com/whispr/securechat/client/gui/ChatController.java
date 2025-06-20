package com.whispr.securechat.client.gui;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.collections.ObservableList; // Dla ListView
import com.whispr.securechat.client.ChatClient;
import com.whispr.securechat.common.User;

import java.awt.desktop.SystemSleepEvent;
import java.util.Set;
//public class ChatController{

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
    private SceneSwitcher sceneSwitcher;

    public void setChatClient(ChatClient client) {
        this.chatClient = client;
        if (client != null) {
            client.setMessageReceivedListener(this);
            client.setUserListListener(this);
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


    @FXML
    private void handleListUpdateButtom() {
        if (chatClient != null) {
            System.out.println("doesnt work handleListUpdateButtom ");
        }
        try {
        chatClient.sendServerUPdateListRequest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }





    // interfeace to change scene
    public interface SceneSwitcher  {
        void switchToLoginScene();
    }
    public void setSceneSwitcher(SceneSwitcher switcher) {
        this.sceneSwitcher = switcher;
    }

    public interface LoginSuccessHandler {
       public void  onLoginSuccess(ChatClient client);
    }
    public void setLoginSuccessHandler(LoginSuccessHandler handler) {   }

    @FXML
    private void initialize() {
        // Inicjalizacja komponentów GUI i listenerów
        if (messages == null) {
            messages = javafx.collections.FXCollections.observableArrayList();
        }
        if (users == null) {
            users = javafx.collections.FXCollections.observableArrayList();
        }
        chatMessagesListView.setItems(messages);
        usersListView.setItems(users);
    }

    @FXML
    private void handleSendMessageButtonAction() {
        // Logika wysyłania wiadomości
        String message = messageInputArea.getText().trim();
        User recipient = usersListView.getSelectionModel().getSelectedItem();
        if (!message.isEmpty() && chatClient != null && recipient != null) {
            try {
                chatClient.sendMessage(recipient.getUsername(), message);
                messages.add("Me: " + message);
                messageInputArea.clear();
            } catch (Exception e) {
                messages.add("Error: " + e.getMessage());
            }
        }
    }



    @Override
    public void onMessageReceived(String sender, String content) {
        Platform.runLater(() -> {
            messages.add(sender + ": " + content); //
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

