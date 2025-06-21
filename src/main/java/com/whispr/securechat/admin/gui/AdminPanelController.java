package com.whispr.securechat.admin.gui;

import com.whispr.securechat.admin.AdminClient;
import com.whispr.securechat.common.User;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextInputDialog;

import java.util.Optional;
import java.util.Set;

public class AdminPanelController {

    private AdminClient adminClient;

    @FXML
    private ListView<User> usersListView;
    @FXML
    private TextArea logTextArea;
    @FXML
    private Button kickUserButton;
    @FXML
    private Button resetPasswordButton;

    @FXML
    private void initialize() {
        kickUserButton.setOnAction(event -> handleKickUserButtonAction());
        resetPasswordButton.setOnAction(event -> handleResetPasswordButtonAction());
    }

    private void handleKickUserButtonAction() {
        User selectedUser = usersListView.getSelectionModel().getSelectedItem();
        if (selectedUser != null) {
            System.out.println("Attempting to kick user: " + selectedUser.getUsername());
            if (adminClient != null) {
                adminClient.sendKickUserRequest(selectedUser.getUsername());
            }
        } else {
            System.out.println("No user selected to kick.");
        }
    }

    private void handleResetPasswordButtonAction() {
        User selectedUser = usersListView.getSelectionModel().getSelectedItem();
        if (selectedUser == null) {
            appendLogMessage("SYSTEM: Please select a user to reset their password.");
            return;
        }

        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("Password Reset");
        dialog.setHeaderText("Reset password for " + selectedUser.getUsername());
        dialog.setContentText("Please enter the new password:");

        Optional<String> result = dialog.showAndWait();
        result.ifPresent(newPassword -> {
            if (newPassword.isBlank()) {
                appendLogMessage("SYSTEM: Password cannot be empty.");
            } else {
                System.out.println("Attempting to reset password for user: " + selectedUser.getUsername());
                if (adminClient != null) {
                    adminClient.sendResetPasswordRequest(selectedUser.getUsername(), newPassword);
                }
            }
        });
    }

    public void setAdminClient(AdminClient client) {
        this.adminClient = client;
    }

    public void updateUserList(Set<User> allOnlineUsers) {
        Platform.runLater(() -> {
            usersListView.getItems().setAll(allOnlineUsers);
        });
    }

    public void appendLogMessage(String logMessage) {
        Platform.runLater(() -> {
            logTextArea.appendText(logMessage + "\n");
        });
    }
}