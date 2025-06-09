package com.whispr.securechat.common;

// Nie musi implementować Serializable, bo serializujemy ją do JSON (String)
// za pomocą Gson, a nie jako obiekt Javy.
public class LoginPayload {
    private final String username;
    private final String password;

    public LoginPayload(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}