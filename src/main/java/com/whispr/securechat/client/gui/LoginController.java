package com.whispr.securechat.client.gui;


import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.TextField;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Label;
import com.whispr.securechat.client.ChatClient;

public class LoginController {
    @FXML
    private TextField usernameField;
    @FXML
    private PasswordField passwordField;
    @FXML
    private Label statusLabel; // Etykieta do wyświetlania komunikatów o błędach/sukcesie
    private LoginSuccessHandler loginSuccessHandler;
    private ChatClient chatClient; // Referencja do instancji ChatClient

    public void setChatClient(ChatClient client) { this.chatClient = client; }


    // interface used if login is succesed
    public interface LoginSuccessHandler {
        void onLoginSuccess(ChatClient client);
    }
    public void setLoginSuccessHandler(LoginSuccessHandler handler) {
        this.loginSuccessHandler = handler;
    }

    @FXML
    private void handleLoginButtonAction() {
        // Logika obsługująca kliknięcie przycisku logowania
        String username = usernameField.getText();
        String password = passwordField.getText();
        // Uruchamiamy nowy wątek, aby nie blokować interfejsu użytkownika
        new Thread(() -> {
            try {
                // Cały proces logowania (włącznie z połączeniem) wykonuje się w tle.
                Platform.runLater(() -> showMessage("Server connecting ", false));
                performKeyExchange();
                Platform.runLater(() -> showMessage("Key exchange", false));
                Platform.runLater(() -> showMessage("user logging ", false));
                chatClient.login(username, password);
                System.out.println("User " + username + " logged in.");
                Platform.runLater(() -> {
                    if (loginSuccessHandler != null) {
                        loginSuccessHandler.onLoginSuccess(chatClient);
                    }
                });
            } catch (Exception e) {
                e.printStackTrace();
                Platform.runLater(() -> showMessage("Error " + e.getMessage(), true));
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
        // Logika obsługująca kliknięcie przycisku rejestracji
        String username = usernameField.getText();
        String password = passwordField.getText();
        new Thread(() -> {
            try {
                Platform.runLater(() -> showMessage("Server connecting ", false));
                chatClient.connect();
                Platform.runLater(() -> showMessage("Key exchange", false));
                performKeyExchange();
                Platform.runLater(() -> showMessage("Asking server for register", false));
                chatClient.register(username, password);
                Platform.runLater(() -> showMessage("Try to log in", false));
            } catch (Exception e) {
                e.printStackTrace();
                Platform.runLater(() -> showMessage("Register error " + e.getMessage(), true));
            }
        }).start();

    }

    private void showMessage(String message, boolean isError) {
        // Wyświetla komunikat dla użytkownika
        statusLabel.setText(message);
        statusLabel.setStyle(isError ? "-fx-text-fill: #ff0000;" : "-fx-text-fill: #176817;");
    }
}
