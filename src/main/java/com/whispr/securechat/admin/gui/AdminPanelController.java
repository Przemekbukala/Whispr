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
    /** Client for communicating with the server with administrative privileges */
    private AdminClient adminClient;
    /** ListView displaying all users registered in the system */
    @FXML
    private ListView<User> usersListView;
    @FXML
    private TextArea logTextArea;
    @FXML
    private Button kickUserButton;
    @FXML
    private Button resetPasswordButton;
    /**
     * Initializes the controller after FXML fields are injected.
     * It sets up event handlers for the UI buttons to respond to user interactions.
     */
    @FXML
    private void initialize() {
        kickUserButton.setOnAction(event -> handleKickUserButtonAction());
        resetPasswordButton.setOnAction(event -> handleResetPasswordButtonAction());
    }
    /**
     * Handles the kick user button click event.
     * This method is triggered when the admin clicks the "Kick User" button.
     * If no user is selected, a message is logged to the console.
     */
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

    /**
     * Handles the reset password button click event.
     * <p>
     * This method is triggered when the admin clicks the "Reset Password" button. It gets the
     * currently selected user from the users list view and displays a dialog to prompt for
     * the new password. If a password is provided, it sends a request to the server to update
     * that user's password in the database.
     * <p>
     * If no user is selected or an empty password is provided, error messages
     * are displayed in the log area.
     */
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
    /**
     * Sets the AdminClient instance for this controller.
     * @param client The AdminClient instance.
     */
    public void setAdminClient(AdminClient client) {
        this.adminClient = client;
    }
    /**
     * Updates the user list in the UI with the latest set of users from the server.
     * <p>
     * This method is called when the AdminApplication receives an updated user list from
     * the server. It updates the items in the usersListView to display the current set of
     * users.
     * @param allOnlineUsers The current set of users registered with the system
     */
    public void updateUserList(Set<User> allOnlineUsers) {
        Platform.runLater(() -> {
            usersListView.getItems().setAll(allOnlineUsers);
        });
    }

    /**
     * Appends a log message to the log text area in the UI.
     * <p>
     *It appends the message to the logTextArea with a newline character.
     * @param logMessage The log message to be displayed
     */
    public void appendLogMessage(String logMessage) {
        Platform.runLater(() -> {
            logTextArea.appendText(logMessage + "\n");
        });
    }
}