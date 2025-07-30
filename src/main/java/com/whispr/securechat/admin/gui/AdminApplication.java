package com.whispr.securechat.admin.gui;
import com.whispr.securechat.admin.AdminClient;
import com.whispr.securechat.admin.AdminClientListener;
import com.whispr.securechat.common.Constants;
import com.whispr.securechat.common.User;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import java.util.Set;

/**
 * This class initializes the admin interface, connects to the chat server, and handles
 * communication between the AdminClient and the UI controller. It implements the AdminClientListener.
 * <p>
 * The application automatically connects to the server on startup and attempts to log in
 * with administrator credentials when the secure session is established.
 */
public class AdminApplication extends Application implements AdminClientListener {
    private final AdminClient adminClient = new AdminClient("localhost");
    /** Controller for the admin panel UI */
    private AdminPanelController controller;
    /**
     * Launches the JavaFX application which initializes the admin interface and
     * establishes a connection to the chat server.*
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        launch(args);
    }
    /**
     * Initializes the JavaFX application and sets up the admin panel interface.
     * <p>
     * This method loads the FXML for the admin panel, connects the controller to the AdminClient,
     * registers this class as the listener for AdminClient events, and establishes the
     * connection to the server. It also configures and displays the primary stage for the
     * admin panel UI.
     * @param primaryStage The primary stage for this application
     * @throws Exception If an error occurs during initialization
     */
    @Override
    public void start(Stage primaryStage) throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/whispr/securechat/admin/gui/AdminPanel.fxml"));
        Parent root = loader.load();

        this.controller = loader.getController();
        this.controller.setAdminClient(adminClient);
        adminClient.setListener(this);
        adminClient.connect();
        Scene scene = new Scene(root, 800, 600);
        primaryStage.setTitle("Admin Panel - Whispr");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    /**
     * Handles the event when the secure session with the server is established.
     * <p>
     * This method is called by the AdminClient when the encrypted communication channel
     * with the server is ready. It automatically initiates the admin login process using
     * the default admin credentials from the Constants class.
     */
    @Override
    public void onSessionReady() {
        System.out.println("GUI: Session is ready. Ready to send login request.");
        adminClient.sendAdminLogin("admin",Constants.ADMIN_PASSWORD);
    }
    /**
     * Handles the server's response to an admin login attempt.
     * <p>
     * This method is called when the server responds to the admin login request.
     * It logs the result of the login attempt to the console.
     * @param success True if the login was successful, false otherwise.
     * @param message The message from the server about the login result.
     */
    @Override
    public void onLoginResponse(boolean success, String message) {
        System.out.println("GUI: Login response received. Success: " + success + ", Message: " + message);
    }
    /**
     * Handles updates to the user list from the server.
     * <p>
     * This method is called when the server sends an updated list of users to the admin client.
     * @param users The updated set of users currently registered with the system.
     */
    @Override
    public void onUserListUpdated(Set<User> users) {
        System.out.println("ADMIN_APP: Received upadated user list: " + users.size());
        if (controller != null) {
            controller.updateUserList(users);
        }
    }

    /**
     * Handles new log messages from the server.
     * This method is called when the server sends a log message to the admin client.
     * It forwards the message to the AdminPanelController to be displayed in the log
     * area of the admin panel UI.
     * @param logMessage The log message from the server
     */
    @Override
    public void onNewLogMessage(String logMessage) {
        controller.appendLogMessage(logMessage);
    }
}
