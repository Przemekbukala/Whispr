package com.whispr.securechat.common;

import com.google.gson.annotations.SerializedName;

import java.util.Objects;

public class User {
    public String getUsername() {
        return username;
    }

    @SerializedName("username")
    private String username;
    @SerializedName("isOnline")
    private boolean isOnline;

    public User(String username, boolean isOnline){
        this.username = username;
        this.isOnline = isOnline;
    }

    @Override
    public String toString(){
        return this.username;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(username, user.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username);
    }

}
