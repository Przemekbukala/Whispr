package com.whispr.securechat.admin.gui;

import com.whispr.securechat.admin.AdminClient;
import com.whispr.securechat.common.User;
import com.whispr.securechat.server.networking.ClientManager;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;

import java.util.Set;

public class AdminPanelController implements ServerStateListener {

    private AdminClient adminClient;
    private ClientManager clientManager;

    @FXML
    private ListView<User> usersListView;

    @FXML
    private TextArea logTextArea;

    @FXML
    private Button kickUserButton;
    @FXML
    private Button resetPasswordButton;

    public void init(ClientManager clientManager) {
        this.clientManager= clientManager;
        // Użyj nowej metody z AdminClient do zarejestrowania tego kontrolera jako słuchacza
        this.clientManager.addListener(this);
    }

    @Override
    public void onUserListChanged(Set<User> allOnlineUsers) {
        // Używamy Platform.runLater, aby bezpiecznie zaktualizować GUI z innego wątku
        Platform.runLater(() -> {
            usersListView.getItems().setAll(allOnlineUsers);
        });
    }

    @Override
    public void onNewLogMessage(String logMessage) {
        // Używamy Platform.runLater z tego samego powodu
        Platform.runLater(() -> {
            logTextArea.appendText(logMessage + "\n");
        });
    }
}