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


public class AdminApplication extends Application implements AdminClientListener {
    private final AdminClient adminClient = new AdminClient("localhost");
    private AdminPanelController controller;

    public static void main(String[] args) {
        launch(args);
    }

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

    @Override
    public void onSessionReady() {
        System.out.println("GUI: Session is ready. Ready to send login request.");
        adminClient.sendAdminLogin("admin",Constants.ADMIN_PASSWORD);
    }

    @Override
    public void onLoginResponse(boolean success, String message) {
        System.out.println("GUI: Login response received. Success: " + success + ", Message: " + message);
    }

    @Override
    public void onUserListUpdated(Set<User> users) {
        System.out.println("ADMIN_APP: Received upadated user list: " + users.size()); // DODAJ TĘ LINIĘ

        if (controller != null) {
            controller.updateUserList(users);
        }
    }

    @Override
    public void onNewLogMessage(String logMessage) {
        controller.appendLogMessage(logMessage);
    }
}
