package com.whispr.securechat.client.gui;


import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import com.whispr.securechat.client.ChatClient;
import com.whispr.securechat.common.Constants;

public class MainApplication extends Application {
    private ChatClient chatClient;
    private Stage primaryStage;

    @Override
    public void start(Stage primaryStage) throws Exception {
        this.primaryStage = primaryStage;
        this.primaryStage.setTitle("Secure Chat Application");

        // Inicjalizacja ChatClient
        chatClient = new ChatClient("localhost", Constants.SERVER_PORT); // Zakładamy lokalny serwer

        showLoginScreen(); // Wyświetlenie ekranu logowania na start
    }

    public static void main(String[] args) {
        launch(args);
    }

    public void showLoginScreen() throws Exception {
        // Ładowanie FXML ekranu logowania i ustawianie kontrolera
    }

    public void showChatScreen() throws Exception {
        // Ładowanie FXML ekranu czatu i ustawianie kontrolera
    }

    @Override
    public void stop() {
        // Zamykanie połączenia z serwerem po zamknięciu aplikacji
        if (chatClient != null) {
            chatClient.disconnect();
        }
    }
}
