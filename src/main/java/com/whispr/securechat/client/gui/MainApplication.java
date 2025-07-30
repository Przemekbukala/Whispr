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

/**
 * Main application class for this secure chat client.
 * The application implements multiple listener interfaces:
 * <ul>
 *   <li>LoginSuccessHandler - To be notified when a user successfully logs in</li>
 *   <li>SceneSwitcher - To handle navigation between different screens</li>
 *   <li>KickedListener - To be notified when the user is kicked from the server</li>
 * </ul>
 */
public class MainApplication extends Application implements LoginController.LoginSuccessHandler, ChatController.SceneSwitcher, ChatClient.KickedListener {
    /** Client instance for secure communication with the chat server */
    private ChatClient chatClient;
    /** Primary stage for the JavaFX application */
    private Stage primaryStage;
    /** Reference to the chat controller when the chat screen is active */
    private ChatController controller;
    /**
     * Initializes the application when it is launched.
     * @param primaryStage The primary stage for this application
     * @throws Exception If an error occurs during initialization
     */
    @Override
    public void start(Stage primaryStage) throws Exception {
        this.primaryStage = primaryStage;
        this.primaryStage.setTitle("Secure Chat Application");
        chatClient = new ChatClient("localhost", Constants.SERVER_PORT); // Using local server
        showLoginScreen();
    }

    /**
     * The main entry point for the application.
     * @param args Command line arguments (not used).
     */
    public static void main(String[] args) {
        System.out.println("Starting the Secure Chat Application...");
        launch(args);
    }

    /**
     * Handles successful login events from the login screen.
     * @param client The authenticated ChatClient instance
     */
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
    /**
     * Loads and displays the login screen.
     * This method loads the Login.fxml file, retrieves the LoginController,
     * configures it with the current ChatClient instance and this class as the
     * login success handler, and displays the login scene on the primary stage.
     */
    public void showLoginScreen() {
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
    /**
     * Switches from the chat screen back to the login screen.
     * <p>
     * This method is called by the ChatController when the user logs out or is
     * disconnected.
     */
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
                System.err.println("Error while switchToLoginScene: " + e.getMessage());
            }
        });
    }
    /**
     * Loads and displays the chat screen.
     * This method is called after a successful login.
     * @throws Exception If an error occurs while loading or displaying the chat screen.
     */
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
    /**
     * Handles kick events from the server.
     * <p>
     * This method is called by the ChatClient when the server kicks the user.
     * It displays an alert dialog with the reason for being kicked and then closes
     * the application.
     * @param reason The reason why the user was kicked from the server (default kickNote)
     */
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

    /**
     * Cleans up resources when the application is closing.
     */
    @Override
    public void stop() {
        if (chatClient != null) {
            chatClient.disconnect();
        }
    }
}
