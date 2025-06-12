package com.whispr.securechat.server.gui;

import com.whispr.securechat.server.ChatServer;
import io.github.palexdev.materialfx.theming.JavaFXThemes;
import io.github.palexdev.materialfx.theming.MaterialFXStylesheets;
import io.github.palexdev.materialfx.theming.UserAgentBuilder;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;




public class AdminApplication extends Application {
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
        UserAgentBuilder.builder()
                .themes(JavaFXThemes.MODENA) // Ustawia bazowy motyw JavaFX
                .themes(MaterialFXStylesheets.forAssemble(true)) // Dodaje wszystkie potrzebne style MaterialFX
                .setDeploy(true)
                .setResolveAssets(true)
                .build()
                .setGlobal();

        // 1. Wskazanie i załadowanie pliku FXML z wyglądem
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/whispr/securechat/server/gui/AdminPanel.fxml"));
        Parent root = loader.load();

        // 2. "Most" do logiki serwera
        AdminPanelController controller = loader.getController();
        ChatServer server = ChatServer.getInstance();
        if (server != null) {
            controller.init(server.getClientManager());
        } else {
            System.err.println("SERWER NIE JEST URUCHOMIONY! Panel admina nie może połączyć się z logiką serwera.");
            // Można tu wyświetlić okno błędu
        }

        // 3. Ustawienie sceny i zastosowanie motywu
        Scene scene = new Scene(root, 800, 600);
        primaryStage.setTitle("Panel Administratora - Whispr");
        primaryStage.setScene(scene);
        primaryStage.show();
    }
}
