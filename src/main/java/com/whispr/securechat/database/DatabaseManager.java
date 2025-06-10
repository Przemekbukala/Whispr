package com.whispr.securechat.database;

import com.whispr.securechat.common.Constants;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;
// Importy dla exceptionów

public class DatabaseManager {
    private Connection connection; // Połączenie z bazą danych

    public DatabaseManager() {

    } // Konstruktor będzie nawiązywał połączenie

    public void initializeDatabase() {
        // Tworzy tabelę użytkowników, jeśli nie istnieje
        String sql = "CREATE TABLE IF NOT EXISTS users ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "username TEXT NOT NULL UNIQUE,"
                + "password TEXT NOT NULL"
                + ");";

        try(Connection conn = DriverManager.getConnection(Constants.DB_URL);
            Statement statement = conn.createStatement()){
            statement.execute(sql);
            System.out.println("Table of users successfully created/opened.");
        } catch (SQLException e){
            System.err.println("Critical error during database initialization:" + e.getMessage());
            throw new RuntimeException("The database cannot be initialized. The server stops working.", e);
        }
    }

    public boolean registerUser(String username, String hashedPassword) throws Exception {
        // Dodaje nowego użytkownika do bazy danych
        return false; // True jeśli sukces, false w przeciwnym razie
    }

    public boolean verifyCredentials(String username, String hashedPassword) throws Exception {
        // Sprawdza dane logowania
        return false; // True jeśli prawidłowe, false w przeciwnym razie
    }

    public void closeConnection() {
        // Zamyka połączenie z bazą danych
    }
}