package com.whispr.securechat.client.gui;


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

    private ChatClient chatClient; // Referencja do instancji ChatClient

    public void setChatClient(ChatClient client) { /* ... */ }

    @FXML
    private void handleLoginButtonAction() {
        // Logika obsługująca kliknięcie przycisku logowania
    }

    @FXML
    private void handleRegisterButtonAction() {
        // Logika obsługująca kliknięcie przycisku rejestracji
    }

    private void showMessage(String message, boolean isError) {
        // Wyświetla komunikat dla użytkownika
    }
}
