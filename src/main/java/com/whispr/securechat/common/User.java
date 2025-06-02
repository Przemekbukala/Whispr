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


}
