package com.whispr.securechat.common;

// Nie musi implementować Serializable, bo serializujemy ją do JSON (String)
// za pomocą Gson, a nie jako obiekt Javy.
public class LoginPayload {
    private final String username;
    private final String password;
    private final String publicKey;

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