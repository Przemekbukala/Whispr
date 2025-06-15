package com.whispr.securechat.database;

import com.whispr.securechat.common.Constants;

import java.sql.*;
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
// Importy dla exceptionów

public class DatabaseManager {
    private static final Logger log = LoggerFactory.getLogger(DatabaseManager.class);


    public DatabaseManager() {
    }

    public void initializeDatabase() {
        // Tworzy tabelę użytkowników, jeśli nie istnieje
        String sql = "CREATE TABLE IF NOT EXISTS users ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "username TEXT NOT NULL UNIQUE,"
                + "password TEXT NOT NULL,"
                + "publicKey TEXT NOT NULL"
                + ");";

        try (Connection conn = DriverManager.getConnection(Constants.DB_URL);
             Statement statement = conn.createStatement()) {
            statement.execute(sql);
            System.out.println("Table of users successfully created/opened.");
        } catch (SQLException e) {
            System.err.println("Critical error during database initialization:" + e.getMessage());
            throw new RuntimeException("The database cannot be initialized. The server stops working.", e);
        }
    }

    public boolean registerUser(String username, String password, String publicKey) throws Exception {
        // Dodaje nowego użytkownika do bazy danych
//        Definicja zapytania SQL z placeholderami (?) dla bezpieczeństwa
        String sql = "INSERT INTO users(username, password, publicKey) VALUES(?,?,?)";
        String hashedPassword = PasswordHasher.hashPassword(password);

        try (Connection conn = DriverManager.getConnection(Constants.DB_URL);
             PreparedStatement preparedStatement = conn.prepareStatement(sql)) {
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, hashedPassword);
            preparedStatement.setString(3, publicKey);
            preparedStatement.executeUpdate();

            log.info("New user registered: " + username);
            return true;
        } catch (SQLException e) {
            if (e.getMessage().contains("SQLITE_CONSTRAINT_UNIQUE")) {
                log.warn("Attempting to register a user that already exists: {}", username);
            } else {
                log.error("Database error during user registration: {}", username, e);
            }
            return false;
        }
    }

    public boolean verifyCredentials(String username, String password) throws Exception {
        // Sprawdza dane logowania
        String sql = "SELECT password FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(Constants.DB_URL);
             PreparedStatement preparedStatement = conn.prepareStatement(sql)) {

            preparedStatement.setString(1, username);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                // Pobieramy hash hasła z kolumny "password"
                String storedHashedPassword = resultSet.getString("password");
                return PasswordHasher.checkPassword(password, storedHashedPassword);
            } else {
                log.warn("Failed login attempt. User does not exist: {}", username);
                return false;
            }
        } catch (SQLException e) {
            log.error("Database error during user verification: {}", username, e);
            return false;
        }
    }

    public String getUserPublicKey(String username) throws SQLException {
        String sql = "SELECT publicKey FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(Constants.DB_URL);
             PreparedStatement preparedStatement = conn.prepareStatement(sql)) {
            preparedStatement.setString(1, username);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getString("publicKey"); // CORRECT
            }
        }
        return null;
    }

    public boolean updateUserPublicKey(String username, String publicKey) {
        String sql = "UPDATE users SET publicKey = ? WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(Constants.DB_URL);
             PreparedStatement preparedStatement = conn.prepareStatement(sql)) {

            preparedStatement.setString(1, publicKey);
            preparedStatement.setString(2, username);

            int affectedRows = preparedStatement.executeUpdate();
            if (affectedRows > 0) {
                log.info("Successfully updated public key for user: {}", username);
                return true;
            } else {
                log.warn("Could not update public key. User not found: {}", username);
                return false;
            }
        } catch (SQLException e) {
            log.error("Database error during public key update for user: {}", username, e);
            return false;
        }

    }
}