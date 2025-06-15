package com.whispr.securechat.common;

// Nie musi implementować Serializable, bo serializujemy ją do JSON (String)
// za pomocą Gson, a nie jako obiekt Javy.
public class LoginPayload {
    private final String username;
    private final String password;
    private final String publicKey;

    /**
     * Constructor used for REGISTRATION, which includes the user's public key.
     * @param username The user's desired username.
     * @param password The user's password.
     * @param publicKey The user's public RSA key, encoded as a Base64 string.
     */
    public LoginPayload(String username, String password, String publicKey) {
        this.username = username;
        this.password = password;
        this.publicKey = publicKey;
    }

    /**
     * Overloaded constructor used for LOGIN, which does not require a public key.
     * It calls the main constructor, setting the public key to null.
     * @param username The user's username.
     * @param password The user's password.
     */
    public LoginPayload(String username, String password) {
        this(username, password, null);
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getPublicKey() { return publicKey; }
}