package com.whispr.securechat.common;

import com.google.gson.annotations.SerializedName;

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


}
