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
        createUsersTable();
        createAdminsTable();
    }

    private void createUsersTable(){
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
            log.info("Table 'users' created or already exists.");
        } catch (SQLException e) {
            System.err.println("Critical error during users database initialization:" + e.getMessage());
            log.error("Critical error during 'users' table initialization: {}", e.getMessage());
            throw new RuntimeException("Database initialization failed for users table. The server stops working.", e);
        }
    }

    private void createAdminsTable(){
        String sql = "CREATE TABLE IF NOT EXISTS admins ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "username TEXT NOT NULL UNIQUE,"
                + "password TEXT NOT NULL,"
                + "publicKey TEXT NOT NULL" // publicKey for admin might be useful later
                + ");";

        try (Connection conn = DriverManager.getConnection(Constants.DB_URL);
             Statement statement = conn.createStatement()) {
            statement.execute(sql);
            System.out.println("Table of admins successfully created/opened.");
            log.info("Table 'admins' created or already exists.");
        } catch (SQLException e) {
            System.err.println("Critical error during admins database initialization:" + e.getMessage());
            log.error("Critical error during 'admins' table initialization: {}", e.getMessage());
            throw new RuntimeException("Database initialization failed for admins table.", e);
        }
    }

    public boolean registerUser(String username, String password, String publicKey) throws Exception {
        String sql = "INSERT INTO users(username, password, publicKey) VALUES(?,?,?)";
        String hashedPassword = PasswordHasher.hashPassword(password);

        try (Connection conn = DriverManager.getConnection(Constants.DB_URL);
             PreparedStatement preparedStatement = conn.prepareStatement(sql)) {
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, hashedPassword);
            preparedStatement.setString(3, publicKey);
            preparedStatement.executeUpdate();

            log.info("New user registered: {}", username);
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

    /**
     * Resets the password for a given user.
     * The new password is automatically hashed before being stored.
     * @param username The username of the user to update.
     * @param newPassword The new plaintext password.
     * @return true if the password was successfully reset, false otherwise.
     * @throws Exception if a password hashing error occurs.
     */
    public boolean resetUserPassword(String username, String newPassword) throws Exception {
        String sql = "UPDATE users SET password = ? WHERE username = ?";
        String hashedPassword = PasswordHasher.hashPassword(newPassword);

        try (Connection conn = DriverManager.getConnection(Constants.DB_URL);
             PreparedStatement preparedStatement = conn.prepareStatement(sql)) {

            preparedStatement.setString(1, hashedPassword);
            preparedStatement.setString(2, username);

            int affectedRows = preparedStatement.executeUpdate();
            if (affectedRows > 0) {
                log.info("Successfully reset password for user: {}", username);
                return true;
            } else {
                log.warn("Could not reset password. User not found: {}", username);
                return false;
            }
        } catch (SQLException e) {
            log.error("Database error during password reset for user: {}", username, e);
            return false;
        }
    }

    /**
     * Registers a new administrator in the 'admins' table.
     * Can be used for initial, one-time setup of an admin account.
     * @param username The admin's username.
     * @param password The admin's raw password.
     * @param publicKey The admin's public key.
     * @return true if registration was successful, false otherwise.
     */
    public boolean registerAdmin(String username, String password, String publicKey) throws Exception {
        String sql = "INSERT INTO admins(username, password, publicKey) VALUES(?,?,?)";
        String hashedPassword = PasswordHasher.hashPassword(password);

        try (Connection conn = DriverManager.getConnection(Constants.DB_URL);
             PreparedStatement preparedStatement = conn.prepareStatement(sql)) {
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, hashedPassword);
            preparedStatement.setString(3, publicKey);
            preparedStatement.executeUpdate();

            log.info("New ADMIN registered: {}", username);
            return true;
        } catch (SQLException e) {
            if (e.getMessage().contains("SQLITE_CONSTRAINT_UNIQUE")) {
                log.warn("Attempting to register an admin that already exists: {}", username);
            } else {
                log.error("Database error during admin registration for admin: {}", username, e);
            }
            return false;
        }
    }

    /**
     * Verifies admin credentials against the 'admins' table.
     * @param username The admin's username.
     * @param password The admin's raw password.
     * @return true if credentials are valid, false otherwise.
     */
    public boolean verifyAdminCredentials(String username, String password) throws Exception {
        String sql = "SELECT password FROM admins WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(Constants.DB_URL);
             PreparedStatement preparedStatement = conn.prepareStatement(sql)) {

            preparedStatement.setString(1, username);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                String storedHashedPassword = resultSet.getString("password");
                return PasswordHasher.checkPassword(password, storedHashedPassword);
            } else {
                log.warn("Failed admin login attempt. Admin does not exist: {}", username);
                return false;
            }
        } catch (SQLException e) {
            log.error("Database error during admin verification for admin: {}", username, e);
            return false;
        }
    }

    /**
     * Updates the public key for a specific admin in the 'admins' table.
     * @param username The username of the admin to update.
     * @param publicKey The new public key to be stored (as a Base64 string).
     * @return true if the update was successful, false otherwise.
     */
    public boolean updateAdminPublicKey(String username, String publicKey) {
        String sql = "UPDATE admins SET publicKey = ? WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(Constants.DB_URL);
             PreparedStatement preparedStatement = conn.prepareStatement(sql)) {

            preparedStatement.setString(1, publicKey);
            preparedStatement.setString(2, username);

            int affectedRows = preparedStatement.executeUpdate();
            if (affectedRows > 0) {
                log.info("Successfully updated public key for admin: {}", username);
                return true;
            } else {
                log.warn("Could not update public key. Admin not found: {}", username);
                return false;
            }
        } catch (SQLException e) {
            log.error("Database error during public key update for admin: {}", username, e);
            return false;
        }
    }
}