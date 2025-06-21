package com.whispr.securechat.client.gui;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.stage.Stage;
import com.whispr.securechat.client.ChatClient;
import com.whispr.securechat.common.Constants;
import java.net.URL;

public class MainApplication extends Application implements LoginController.LoginSuccessHandler,  ChatController.SceneSwitcher,ChatClient.KickedListener

{
    private ChatClient chatClient;
    private Stage primaryStage;
    private ChatController controller;
    @Override
    public void start(Stage primaryStage) throws Exception {
        this.primaryStage = primaryStage;
        this.primaryStage.setTitle("Secure Chat Application");
        chatClient = new ChatClient("localhost", Constants.SERVER_PORT); // Zakładamy lokalny serwer
      showLoginScreen();
    }

    public static void main(String[] args) {
        System.out.println("Starting the Secure Chat Application...");
        launch(args);
    }

    public void onLoginSuccess(ChatClient client) {
        this.chatClient = client;
        this.chatClient.setKickedListener(this);
        Platform.runLater(() -> {
            try {
                showChatScreen();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
    public void showLoginScreen(){
        try {
            System.out.println("Loading login screen...");
            URL fxmlLocation = MainApplication.class.getResource("/com/whispr/securechat/client/gui/Login.fxml");
            FXMLLoader loader = new FXMLLoader(fxmlLocation);
            Parent root = loader.load();
            LoginController loginController = loader.getController();
            loginController.setChatClient(chatClient);
            loginController.setLoginSuccessHandler(this);
            primaryStage.setScene(new Scene(root));
            primaryStage.show();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ERROR: Could not load login screen.");
        }
    }
    public void switchToLoginScene() {
        if (chatClient != null) {
            chatClient.disconnect();
            chatClient = null;
        }
        Platform.runLater(() -> {
            try {
                chatClient = new ChatClient("localhost", Constants.SERVER_PORT);
                showLoginScreen();
            } catch (Exception e) {
                e.printStackTrace();
                System.err.println("Error while  switchToLoginScene" + e.getMessage());
            }
        });
    }


    public void showChatScreen() throws Exception {
        URL fxmlLocation = MainApplication.class.getResource("/com/whispr/securechat/client/gui/ClientPanel.fxml");
        FXMLLoader loader = new FXMLLoader(fxmlLocation);
        Parent root = loader.load();
        controller = loader.getController();
        controller.setChatClient(chatClient);
        Scene scene = new Scene(root, 800, 600);
        controller.setSceneSwitcher(this);
        primaryStage.setScene(scene);
        primaryStage.show();
    }
    @Override
    public void onKicked(String reason) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("Disconnected");
            alert.setHeaderText("You have been kicked from the server.");
            alert.setContentText(reason);
            alert.showAndWait();
            if (primaryStage != null) {
                primaryStage.close();
            }
        });
    }

    @Override
    public void stop() {
        if (chatClient != null) {
            chatClient.disconnect();
        }
    }
}
