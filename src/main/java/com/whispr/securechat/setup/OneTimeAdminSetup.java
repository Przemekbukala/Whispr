package com.whispr.securechat.setup;

import com.whispr.securechat.database.DatabaseManager;
import com.whispr.securechat.security.RSAEncryptionUtil;

import java.security.KeyPair;
import java.util.Base64;

public class OneTimeAdminSetup {

    /**
     * This main method is for one-time execution to register an admin user.
     * Run this once to populate the database.
     */
    public static void main(String[] args) {
        System.out.println("Attempting to register the initial admin account...");

        DatabaseManager dbManager = new DatabaseManager();

        dbManager.initializeDatabase();

        // Admin credentials
        String adminUsername = "admin";
        String adminPassword = "1234";

        try {

            KeyPair adminKeyPair = RSAEncryptionUtil.generateRSAKeyPair();
            String adminPublicKeyB64 = Base64.getEncoder().encodeToString(adminKeyPair.getPublic().getEncoded());

            boolean success = dbManager.registerAdmin(adminUsername, adminPassword, adminPublicKeyB64);

            if (success) {
                System.out.println("SUCCESS: Admin '" + adminUsername + "' registered successfully.");
                System.out.println("You can now log in with this username and password.");
            } else {
                System.err.println("FAILURE: Admin could not be registered. It might already exist in the database.");
            }

        } catch (Exception e) {
            System.err.println("An error occurred during admin setup: " + e.getMessage());
            e.printStackTrace();
        }
    }
}