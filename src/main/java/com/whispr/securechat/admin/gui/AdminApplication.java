package com.whispr.securechat.admin.gui;

import com.whispr.securechat.admin.AdminClient;
import com.whispr.securechat.admin.AdminClientListener;
import com.whispr.securechat.common.Constants;
import com.whispr.securechat.server.ChatServer;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.stage.Stage;

import java.util.Optional;


public class AdminApplication extends Application implements AdminClientListener {
    private AdminClient adminClient;
    private Stage primaryStage;
    private String enteredPassword;

    public static void main(String[] args) {
// Ta metoda uruchomi całą aplikację JavaFX
        launch(args);
    }
    @Override
    public void start(Stage primaryStage) {
        this.primaryStage = primaryStage;
        promptForPassword();
    }

    private void promptForPassword() {
        Dialog<String> dialog = new Dialog<>();
        dialog.setTitle("Admin Login");
        dialog.setHeaderText("Authentication Required");

// Typy przycisków
        ButtonType loginButtonType = ButtonType.OK;
        dialog.getDialogPane().getButtonTypes().addAll(loginButtonType, ButtonType.CANCEL);
// Layout making
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(20, 150, 10, 10));

// Maskowanie hasła
        PasswordField passwordField = new PasswordField();
        passwordField.setPromptText("Password");
        grid.add(new Label("Password:"), 0, 0);
        grid.add(passwordField, 1, 0);

// wył. login
        Node loginButton = dialog.getDialogPane().lookupButton(loginButtonType);
        loginButton.setDisable(true);

        passwordField.textProperty().addListener((observable, oldValue, newValue) -> {
            loginButton.setDisable(newValue.trim().isEmpty());
        });

        dialog.getDialogPane().setContent(grid);
        Platform.runLater(passwordField::requestFocus);

        dialog.setResultConverter(dialogButton -> {

            if (dialogButton == loginButtonType) {
                return passwordField.getText();
            }
            return null;
        });
        Optional<String> result = dialog.showAndWait();
        result.ifPresentOrElse(
                password -> {
                    this.enteredPassword = password;
                    initializeNetworkConnection();
                },
                () -> {
                    System.out.println("Login cancelled by user.");
                    Platform.exit();
                }
        );
    }


    private void initializeNetworkConnection() {
        adminClient = new AdminClient("localhost");
        adminClient.setListener(this);
        adminClient.connect();
    }


    private void showAdminPanel() throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/whispr/securechat/admin/gui/AdminPanel.fxml"));
        Parent root = loader.load();
        Scene scene = new Scene(root, 800, 600);
        primaryStage.setTitle("Admin Panel - Whispr");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    @Override
    public void onSessionReady() {
        if (adminClient != null && enteredPassword != null) {
            System.out.println("GUI: Session is ready. Sending login request.");
            adminClient.sendAdminLogin(enteredPassword);
        }
    }

    @Override
    public void onLoginResponse(boolean success, String message) {
        System.out.println("DEBUG: onLoginResponse triggered. Success: " + success + ", Message: '" + message + "'");
        Platform.runLater(() -> {
            if (success) {
//                Alert alert = new Alert(Alert.AlertType.INFORMATION);
//                alert.setTitle("Success");
//                alert.setHeaderText("Login Successful");
//                alert.setContentText(message);
//                alert.showAndWait();
                try {
                    showAdminPanel();
                } catch (Exception e) {
                    System.err.println("Error while openning admin panel.");
                }
            } else {
                Alert alert = new Alert(Alert.AlertType.ERROR);
                alert.setTitle("Login Failed");
                alert.setHeaderText("Authentication Failed");
                alert.setContentText(message);
                alert.showAndWait();
                promptForPassword();

            }

        });

    }

}
