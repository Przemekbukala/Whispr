package com.whispr.securechat.database;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

class DatabaseManagerTest {

    private DatabaseManager dbManager;
    private static final String TEST_DB_URL = "jdbc:sqlite::memory:";

    @BeforeEach
    void setUp() {
        dbManager = new DatabaseManager(TEST_DB_URL);
        dbManager.initializeDatabase();
    }

    @AfterEach
    void tearDown() {
        dbManager.close();
    }

    @Test
    void testRegisterUserAndVerifyCredentials() {
        boolean registered = dbManager.registerUser("testuser", "password123", "publicKey1");
        assertTrue(registered, "User should be registered successfully.");

        boolean verified = dbManager.verifyCredentials("testuser", "password123");
        assertTrue(verified, "Credentials should be verified successfully.");

        boolean verifiedWrongPass = dbManager.verifyCredentials("testuser", "wrongpassword");
        assertFalse(verifiedWrongPass, "Verification with wrong password should fail.");
    }

    @Test
    void testRegisterExistingUserFails() {
        dbManager.registerUser("existinguser", "password", "key1");
        boolean registeredAgain = dbManager.registerUser("existinguser", "newpassword", "key2");
        assertFalse(registeredAgain, "Registering an existing user should fail.");
    }

    @Test
    void testGetUserPublicKey() throws SQLException {
        dbManager.registerUser("userwithkey", "pass", "publicKeyString");
        String publicKey = dbManager.getUserPublicKey("userwithkey");
        assertEquals("publicKeyString", publicKey, "Should retrieve the correct public key.");
    }

    @Test
    void testGetUserPublicKeyForNonexistentUser() throws SQLException {
        String publicKey = dbManager.getUserPublicKey("nonexistent");
        assertNull(publicKey, "Public key for a nonexistent user should be null.");
    }

    @Test
    void testUpdateUserPublicKey() throws SQLException {
        dbManager.registerUser("userToUpdate", "pass", "initialKey");
        boolean updated = dbManager.updateUserPublicKey("userToUpdate", "updatedKey");
        assertTrue(updated, "Public key should be updated successfully.");

        String newKey = dbManager.getUserPublicKey("userToUpdate");
        assertEquals("updatedKey", newKey, "The retrieved key should be the updated one.");
    }

    @Test
    void testResetUserPassword() {
        dbManager.registerUser("userPassReset", "oldPassword", "key");
        boolean reset = dbManager.resetUserPassword("userPassReset", "newPassword");
        assertTrue(reset, "Password should be reset successfully.");

        boolean verifyOld = dbManager.verifyCredentials("userPassReset", "oldPassword");
        assertFalse(verifyOld, "Verification with old password should fail.");

        boolean verifyNew = dbManager.verifyCredentials("userPassReset", "newPassword");
        assertTrue(verifyNew, "Verification with new password should succeed.");
    }

    @Test
    void testRegisterAdminAndVerifyCredentials() {
        boolean registered = dbManager.registerAdmin("testadmin", "adminPass", "adminKey");
        assertTrue(registered, "Admin should be registered successfully.");

        boolean verified = dbManager.verifyAdminCredentials("testadmin", "adminPass");
        assertTrue(verified, "Admin credentials should be verified successfully.");

        boolean verifiedWrongPass = dbManager.verifyAdminCredentials("testadmin", "wrongAdminPass");
        assertFalse(verifiedWrongPass, "Admin verification with wrong password should fail.");
    }

    @Test
    void testUpdateAdminPublicKey() {
        dbManager.registerAdmin("adminToUpdate", "pass", "initialAdminKey");
        boolean updated = dbManager.updateAdminPublicKey("adminToUpdate", "updatedAdminKey");
        assertTrue(updated, "Admin public key should be updated successfully.");
    }
}