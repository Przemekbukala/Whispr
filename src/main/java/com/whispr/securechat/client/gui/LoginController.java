package com.whispr.securechat.client.gui;


import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.TextField;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Label;
import com.whispr.securechat.client.ChatClient;

public class LoginController implements ChatClient.SessionStateListener, ChatClient.AuthListener {
    @FXML
    private TextField usernameField;
    @FXML
    private PasswordField passwordField;
    @FXML
    private Label statusLabel; // Etykieta do wyświetlania komunikatów o błędach/sukcesie
    private LoginSuccessHandler loginSuccessHandler;
    private ChatClient chatClient; // Referencja do instancji ChatClient
    private boolean isSessionReady = false;

    public void setChatClient(ChatClient client) {
        this.chatClient = client;
        this.chatClient.setSessionStateListener(this);
        this.chatClient.setAuthListener(this);
    }

    @FXML
    private void initialize() {
        // Połącz i rozpocznij wymianę kluczy zaraz po inicjalizacji
        new Thread(() -> {
            try {
                Platform.runLater(() -> showMessage("Connecting to server...", false));
                chatClient.connect();
                chatClient.sendClientPublicRSAKey(); // Rozpocznij wymianę
            } catch (Exception e) {
                Platform.runLater(() -> showMessage("Connection failed: " + e.getMessage(), true));
            }
        }).start();
    }

    // interface used if login is succesed
    public interface LoginSuccessHandler {
        void onLoginSuccess(ChatClient client);
    }

    @FXML
    private void handleLoginButtonAction() {
        String username = usernameField.getText();
        String password = passwordField.getText();

        if (username.isBlank() || password.isBlank()) {
            showMessage("The user name and password must not be empty.", true);
            return;
        }

        if (!isSessionReady) {
            showMessage("Session not established. Please wait.", true);
            return;
        }

        new Thread(() -> {
            try {
                Platform.runLater(() -> showMessage("Logging in...", false));
                chatClient.login(username, password);
            } catch (Exception e) {
                Platform.runLater(() -> showMessage("Login error: " + e.getMessage(), true));
            }
        }).start();
    }

    // to make code simpler
    private void performKeyExchange() throws Exception {
        chatClient.connect();
        chatClient.sendClientPublicRSAKey();
        Thread.sleep(500);
        chatClient.sendClientAESKey();
        Thread.sleep(500);
    }

    @FXML
    private void handleRegisterButtonAction() {
        String username = usernameField.getText();
        String password = passwordField.getText();

        if (username.isBlank() || password.isBlank()) {
            showMessage("The user name and password must not be empty.", true);
            return;
        }

        if (!isSessionReady) {
            showMessage("Session not established. Please wait.", true);
            return;
        }

        new Thread(() -> {
            try {
                Platform.runLater(() -> showMessage("Registering...", false));
                chatClient.register(username, password);
            } catch (Exception e) {
                Platform.runLater(() -> showMessage("Registration error: " + e.getMessage(), true));
            }
        }).start();
    }

    @Override
    public void onSessionEstablished() {
        this.isSessionReady = true;
        Platform.runLater(() -> showMessage("Secure session established. Ready to log in or register.", false));
    }

    @Override
    public void onSessionFailed(String reason) {
        this.isSessionReady = false;
        Platform.runLater(() -> showMessage("Session setup failed: " + reason, true));
    }

    // Metody z interfejsu AuthListener
    @Override
    public void onLoginSuccess() {
        Platform.runLater(() -> {
            showMessage("Login successful!", false);
            if (loginSuccessHandler != null) {
                loginSuccessHandler.onLoginSuccess(chatClient);
            }
        });
    }

    @Override
    public void onLoginFailure(String reason) {
        Platform.runLater(() -> showMessage("Login failed: " + reason, true));
    }

    @Override
    public void onRegisterSuccess() {
        Platform.runLater(() -> showMessage("Registration successful! You can now log in.", false));
    }

    @Override
    public void onRegisterFailure(String reason) {
        Platform.runLater(() -> showMessage("Registration failed: " + reason, true));
    }

    private void showMessage(String message, boolean isError) {
        statusLabel.setText(message);
        statusLabel.setStyle(isError ? "-fx-text-fill: #ff0000;" : "-fx-text-fill: #176817;");
    }

    public void setLoginSuccessHandler(LoginSuccessHandler handler) {
        this.loginSuccessHandler = handler;
    }

}
