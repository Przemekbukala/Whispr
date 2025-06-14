package com.whispr.securechat.admin.gui;

import com.whispr.securechat.admin.AdminClient;
import com.whispr.securechat.admin.AdminClientListener;
import com.whispr.securechat.common.Constants;
import com.whispr.securechat.server.ChatServer;
//import io.github.palexdev.materialfx.theming.JavaFXThemes;
//import io.github.palexdev.materialfx.theming.MaterialFXStylesheets;
//import io.github.palexdev.materialfx.theming.UserAgentBuilder;
//import io.github.palexdev.mfxresources.fonts.MFXFontIcon;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;


public class AdminApplication extends Application implements AdminClientListener {
    private final AdminClient adminClient = new AdminClient("localhost");

    public static void main(String[] args) {
        // Ta metoda uruchomi całą aplikację JavaFX
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        // Opcjonalne: Uruchamia automatyczne przeładowywanie CSS.
        // Przydatne podczas tworzenia wyglądu, można usunąć w wersji produkcyjnej.
        // CSSFX.start();

        // --- POPRAWNY SPOSÓB INICJALIZACJI MOTYWU (zgodnie z Demo.java) ---
        // Ta metoda jest nowsza i bardziej niezawodna niż MFXThemeManager.
        // Ustawia styl globalnie dla całej aplikacji.
//        UserAgentBuilder.builder()
//                .themes(JavaFXThemes.MODENA) // Ustawia bazowy motyw JavaFX
//                .themes(MaterialFXStylesheets.forAssemble(true)) // Dodaje wszystkie potrzebne style MaterialFX
//                .setDeploy(true)
//                .setResolveAssets(true)
//                .build()
//                .setGlobal();

        // 1. Wskazanie i załadowanie pliku FXML z wyglądem
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/whispr/securechat/admin/gui/AdminPanel.fxml"));
        Parent root = loader.load();

        // 2. "Most" do logiki serwera
        AdminPanelController controller = loader.getController();
//        ChatServer server = ChatServer.getInstance();
//        if (server != null) {
//            controller.init(server.getClientManager());
//        } else {
//            System.err.println("SERVER IS NOT RUNNING! The admin panel cannot connect to the server logic.");
//            // Można tu wyświetlić okno błędu
//        }

        adminClient.connect();


        // 3. Ustawienie sceny i zastosowanie motywu
        Scene scene = new Scene(root, 800, 600);

//        scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("admin-styles.css")).toExternalForm());

        primaryStage.setTitle("Admin Panel - Whispr");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    @Override
    public void onSessionReady() {
        // Na razie puste, ale zaraz to wykorzystamy!
        System.out.println("GUI: Session is ready. Ready to send login request.");
        adminClient.sendAdminLogin(Constants.ADMIN_PASSWORD);
    }

    @Override
    public void onLoginResponse(boolean success, String message) {
        // Na razie puste
        System.out.println("GUI: Login response received. Success: " + success + ", Message: " + message);
    }
}
