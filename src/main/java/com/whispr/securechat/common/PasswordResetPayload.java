package com.whispr.securechat.common;

/**
 * Data transfer object for password reset requests.
 * <p>
 * This class encapsulates the information needed to reset a user's password,
 * including the username and the new password to set.
 * </p>
 */
public class PasswordResetPayload {
    /** The username of the account whose password will be reset */
    private final String username;
    /** The new password to set for the account */
    private final String newPassword;
    /**
     * Creates a new password reset payload with the specified username and new password.
     *
     * @param username The username of the account to reset
     * @param newPassword The new password to set
     */
    public PasswordResetPayload(String username, String newPassword) {
        this.username = username;
        this.newPassword = newPassword;
    }

    /**
     * Gets the username of the account whose password will be reset.
     * @return The username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the new password to set for the account.
     *
     * @return The new password
     */
    public String getNewPassword() {
        return newPassword;
    }
}