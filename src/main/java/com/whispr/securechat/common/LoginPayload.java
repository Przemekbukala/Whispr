package com.whispr.securechat.common;

public class LoginPayload {
    private final String username;
    private final String password;
    private final String publicKey;

    /**
     * Constructor used for both REGISTRATION and LOGIN.
     * It includes the user's username, password, and public key.
     * The public key is sent on every login to ensure the server always has the latest key.
     * @param username The user's username.
     * @param password The user's password.
     * @param publicKey The user's public RSA key, encoded as a Base64 string.
     */
    public LoginPayload(String username, String password, String publicKey) {
        this.username = username;
        this.password = password;
        this.publicKey = publicKey;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getPublicKey() { return publicKey; }
}