package com.whispr.securechat.client.gui;


import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.TextField;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Label;
import com.whispr.securechat.client.ChatClient;

/**
 * Controller for the login and registration screen in the Whispr secure chat application.
 * <p>
 * This class handles user authentication, including login and registration operations.
 * It implements the SessionStateListener and AuthListener interfaces to respond to
 * events from the ChatClient related to secure session establishment and authentication
 * results.
 */
public class LoginController implements ChatClient.SessionStateListener, ChatClient.AuthListener {
    /** Text field for entering the username during login or registration */
    @FXML
    private TextField usernameField;
    /** Password field for entering the password during login or registration */
    @FXML
    private PasswordField passwordField;
    /** Label for displaying status messages, errors, and success notifications */
    @FXML
    private Label statusLabel;
    /** Handler that will be notified when login is successful */
    private LoginSuccessHandler loginSuccessHandler;
    /** Client for handling secure communication with the server */
    private ChatClient chatClient;
    /** Flag indicating whether a secure session with the server has been established */
    private boolean isSessionReady = false;

    /**
     * Sets the ChatClient instance for this controller and registers listeners.
     * @param client The ChatClient instance to use for server communication
     */
    public void setChatClient(ChatClient client) {
        this.chatClient = client;
        this.chatClient.setSessionStateListener(this);
        this.chatClient.setAuthListener(this);
    }
    /**
     * Initializes the controller after FXML fields are injected.
     */
    @FXML
    private void initialize() {
        new Thread(() -> {
            try {
                Platform.runLater(() -> showMessage("Connecting to server...", false));
                chatClient.connect();
                chatClient.sendClientPublicRSAKey(); // Start key exchange
            } catch (Exception e) {
                Platform.runLater(() -> showMessage("Connection failed: " + e.getMessage(), true));
            }
        }).start();
    }

    /**
     * Interface for handling successful login events.
     * <p>
     * This interface is implemented by the MainApplication to receive notifications
     * when a user successfully logs in, allowing it to switch to the chat screen.
     */
    public interface LoginSuccessHandler {
        /**
         * Called when a user successfully logs in.
         * @param client The authenticated ChatClient instance
         */
        void onLoginSuccess(ChatClient client);
    }

    /**
     * Handles the login button click event.
     */
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

    /**
     * Handles the register button click event.
     * <p>
     * This method is called when the user clicks the register button. It validates the
     * input fields, checks if a secure session has been established, and then attempts
     * to register a new user account on a background thread.
     */
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

    /**
     * Called when a secure session with the server has been successfully established.
     * <p>
     * This method is invoked by the ChatClient when the secure key exchange process
     * completes successfully. It updates the session state and displays a success
     * message to inform the user that they can now proceed with login or registration.
     */
    @Override
    public void onSessionEstablished() {
        this.isSessionReady = true;
        Platform.runLater(() -> showMessage("Secure session established. Ready to log in or register.", false));
    }

    /**
     * Called when the secure session establishment with the server has failed.
     * <p>
     * This method is invoked by the ChatClient when the secure key exchange process
     * fails. It updates the session state and displays an error message with the reason
     * for the failure.
     *
     * @param reason The reason why the session establishment failed
     */
    @Override
    public void onSessionFailed(String reason) {
        this.isSessionReady = false;
        Platform.runLater(() -> showMessage("Session setup failed: " + reason, true));
    }

    /**
     * Called when a login attempt is successful.
     * <p>
     * This method is invoked by the ChatClient when the server confirms a successful login.
     * It displays a success message and notifies the login success handler, which will
     * typically switch to the chat screen.
     */
    @Override
    public void onLoginSuccess() {
        Platform.runLater(() -> {
            showMessage("Login successful!", false);
            if (loginSuccessHandler != null) {
                loginSuccessHandler.onLoginSuccess(chatClient);
            }
        });
    }

    /**
     * Called when a login attempt fails.
     * <p>
     * This method is invoked by the ChatClient when the server rejects a login attempt.
     * It displays an error message with the reason for the failure.
     *
     * @param reason The reason why the login attempt failed
     */
    @Override
    public void onLoginFailure(String reason) {
        Platform.runLater(() -> showMessage("Login failed: " + reason, true));
    }

    /**
     * Called when a registration attempt is successful.
     * <p>
     * This method is invoked by the ChatClient when the server confirms a successful
     * user registration.
     */
    @Override
    public void onRegisterSuccess() {
        Platform.runLater(() -> showMessage("Registration successful! You can now log in.", false));
    }

    /**
     * Called when a registration attempt fails.
     * <p>
     * This method is invoked by the ChatClient when the server rejects a registration
     * attempt. It displays an error message with the reason for the failure.
     *
     * @param reason The reason why the registration attempt failed
     */
    @Override
    public void onRegisterFailure(String reason) {
        Platform.runLater(() -> showMessage("Registration failed: " + reason, true));
    }

    /**
     * This  method updates the status label with the specified message and
     * sets its color based on whether the message represents an error (red) or
     * a success/informational message (green).
     * @param message The message to display
     * @param isError Whether the message represents an error condition
     */
    private void showMessage(String message, boolean isError) {
        statusLabel.setText(message);
        statusLabel.setStyle(isError ? "-fx-text-fill: #ff0000;" : "-fx-text-fill: #176817;");
    }

    /**
     * Sets the handler for successful login events.
     * <p>
     * This method allows the MainApplication to register a callback that will be
     * invoked when a user successfully logs in.
     * @param handler The LoginSuccessHandler implementation to notify on successful login
     */
    public void setLoginSuccessHandler(LoginSuccessHandler handler) {
        this.loginSuccessHandler = handler;
    }

}
