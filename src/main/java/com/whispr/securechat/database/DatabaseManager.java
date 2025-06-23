package com.whispr.securechat.database;

import com.whispr.securechat.common.Constants;

import java.sql.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages all interactions with the application's SQLite database.
 * This class handles creating tables, registering and authenticating users and admins,
 * and retrieving and updating user data like public keys and passwords.
 * All database operations are centralized here.
 */
public class DatabaseManager {
    private static final Logger log = LoggerFactory.getLogger(DatabaseManager.class);
    private final String dbUrl;
    private Connection connection;

    /**
     * Default constructor for production. Uses the standard database URL from Constants.
     */
    public DatabaseManager() {
        this(Constants.DB_URL);
    }

    /**
     * Constructor for testing. Allows injecting a custom database URL.
     *
     * @param dbUrl The JDBC URL of the database to connect to.
     */
    public DatabaseManager(String dbUrl) {
        this.dbUrl = dbUrl;
        connect();
    }

    /**
     * Establishes and stores a connection to the database.
     */
    private void connect() {
        try {
            if (connection == null || connection.isClosed()) {
                connection = DriverManager.getConnection(this.dbUrl);
                log.info("Database connection established to {}", dbUrl);
            }
        } catch (SQLException e) {
            log.error("Failed to connect to the database at {}", dbUrl, e);
            throw new RuntimeException("Database connection failed.", e);
        }
    }

    /**
     * Closes the active connection to the database.
     */
    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                log.info("Database connection closed.");
            }
        } catch (SQLException e) {
            log.error("Failed to close database connection.", e);
        }
    }

    /**
     * Initializes the database by ensuring that all necessary tables are created.
     * If the tables ('users', 'admins') do not exist, they will be created.
     * This method should be called once when the server starts.
     */
    public void initializeDatabase() {
        createUsersTable();
        createAdminsTable();
    }

    /**
     * Creates the 'users' table in the database if it does not already exist.
     * This table stores user credentials and their public RSA key.
     * Throws a RuntimeException if the table creation fails, as it is a critical startup operation.
     */
    private void createUsersTable() {
        String sql = "CREATE TABLE IF NOT EXISTS users ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "username TEXT NOT NULL UNIQUE,"
                + "password TEXT NOT NULL,"
                + "publicKey TEXT NOT NULL"
                + ");";

        try (Statement statement = this.connection.createStatement()) {
            statement.execute(sql);
            System.out.println("Table of users successfully created/opened.");
            log.info("Table 'users' created or already exists.");
        } catch (SQLException e) {
            System.err.println("Critical error during users database initialization:" + e.getMessage());
            log.error("Critical error during 'users' table initialization: {}", e.getMessage());
            throw new RuntimeException("Database initialization failed for users table. The server stops working.", e);
        }
    }

    /**
     * Creates the 'admins' table in the database if it does not already exist.
     * This table stores administrator credentials and their public RSA key.
     * Throws a RuntimeException if the table creation fails.
     */
    private void createAdminsTable() {
        String sql = "CREATE TABLE IF NOT EXISTS admins ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "username TEXT NOT NULL UNIQUE,"
                + "password TEXT NOT NULL,"
                + "publicKey TEXT NOT NULL"
                + ");";

        try (Statement statement = this.connection.createStatement()) {
            statement.execute(sql);
            System.out.println("Table of admins successfully created/opened.");
            log.info("Table 'admins' created or already exists.");
        } catch (SQLException e) {
            System.err.println("Critical error during admins database initialization:" + e.getMessage());
            log.error("Critical error during 'admins' table initialization: {}", e.getMessage());
            throw new RuntimeException("Database initialization failed for admins table.", e);
        }
    }

    /**
     * Registers a new user in the database.
     * The provided password is automatically hashed using BCrypt before being stored.
     *
     * @param username  The desired username, which must be unique.
     * @param password  The user's plaintext password.
     * @param publicKey The user's public RSA key, encoded as a Base64 string.
     * @return true if the user was successfully registered, false if the username already exists or an error occurred.
     */
    public boolean registerUser(String username, String password, String publicKey) {
        String sql = "INSERT INTO users(username, password, publicKey) VALUES(?,?,?)";
        String hashedPassword = PasswordHasher.hashPassword(password);

        try (PreparedStatement preparedStatement = this.connection.prepareStatement(sql)) {
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

    /**
     * Verifies a user's login credentials against the database.
     *
     * @param username The username of the user attempting to log in.
     * @param password The plaintext password provided by the user.
     * @return true if the username exists and the password matches the stored hash, false otherwise.
     */
    public boolean verifyCredentials(String username, String password) {
        String sql = "SELECT password FROM users WHERE username = ?";
        try (PreparedStatement preparedStatement = this.connection.prepareStatement(sql)) {
            preparedStatement.setString(1, username);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    String storedHashedPassword = resultSet.getString("password");
                    return PasswordHasher.checkPassword(password, storedHashedPassword);
                } else {
                    log.warn("Failed login attempt. User does not exist: {}", username);
                    return false;
                }
            }
        } catch (SQLException e) {
            log.error("Database error during user verification: {}", username, e);
            return false;
        }
    }

    /**
     * Retrieves the public RSA key for a specific user.
     *
     * @param username The username of the user whose key is being requested.
     * @return A string containing the Base64 encoded public key, or null if the user is not found.
     * @throws SQLException if a database access error occurs.
     */
    public String getUserPublicKey(String username) throws SQLException {
        String sql = "SELECT publicKey FROM users WHERE username = ?";
        try (PreparedStatement preparedStatement = this.connection.prepareStatement(sql)) {
            preparedStatement.setString(1, username);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getString("publicKey");
                }
            }
        }
        return null;
    }

    /**
     * Updates the public RSA key for a given user.
     * This is typically done upon login to ensure the server always has the client's latest key.
     *
     * @param username  The username of the user to update.
     * @param publicKey The new public key to store, encoded as a Base64 string.
     * @return true if the key was updated successfully, false if the user was not found or an error occurred.
     */
    public boolean updateUserPublicKey(String username, String publicKey) {
        String sql = "UPDATE users SET publicKey = ? WHERE username = ?";
        try (PreparedStatement preparedStatement = this.connection.prepareStatement(sql)) {
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
     *
     * @param username    The username of the user to update.
     * @param newPassword The new plaintext password.
     * @return true if the password was successfully reset, false otherwise.
     */
    public boolean resetUserPassword(String username, String newPassword) {
        String sql = "UPDATE users SET password = ? WHERE username = ?";
        String hashedPassword = PasswordHasher.hashPassword(newPassword);

        try (PreparedStatement preparedStatement = this.connection.prepareStatement(sql)) {
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
     *
     * @param username  The admin's username.
     * @param password  The admin's raw password.
     * @param publicKey The admin's public key.
     * @return true if registration was successful, false otherwise.
     */
    public boolean registerAdmin(String username, String password, String publicKey) {
        String sql = "INSERT INTO admins(username, password, publicKey) VALUES(?,?,?)";
        String hashedPassword = PasswordHasher.hashPassword(password);

        try (PreparedStatement preparedStatement = this.connection.prepareStatement(sql)) {
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
     *
     * @param username The admin's username.
     * @param password The admin's raw password.
     * @return true if credentials are valid, false otherwise.
     */
    public boolean verifyAdminCredentials(String username, String password) {
        String sql = "SELECT password FROM admins WHERE username = ?";
        try (PreparedStatement preparedStatement = this.connection.prepareStatement(sql)) {
            preparedStatement.setString(1, username);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    String storedHashedPassword = resultSet.getString("password");
                    return PasswordHasher.checkPassword(password, storedHashedPassword);
                } else {
                    log.warn("Failed admin login attempt. Admin does not exist: {}", username);
                    return false;
                }
            }
        } catch (SQLException e) {
            log.error("Database error during admin verification for admin: {}", username, e);
            return false;
        }
    }

    /**
     * Updates the public key for a specific admin in the 'admins' table.
     *
     * @param username  The username of the admin to update.
     * @param publicKey The new public key to be stored (as a Base64 string).
     * @return true if the update was successful, false otherwise.
     */
    public boolean updateAdminPublicKey(String username, String publicKey) {
        String sql = "UPDATE admins SET publicKey = ? WHERE username = ?";
        try (PreparedStatement preparedStatement = this.connection.prepareStatement(sql)) {
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