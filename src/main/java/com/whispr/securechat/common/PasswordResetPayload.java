package com.whispr.securechat.common;

public class PasswordResetPayload {
    private final String username;
    private final String newPassword;

    public PasswordResetPayload(String username, String newPassword) {
        this.username = username;
        this.newPassword = newPassword;
    }

    public String getUsername() {
        return username;
    }

    public String getNewPassword() {
        return newPassword;
    }
}