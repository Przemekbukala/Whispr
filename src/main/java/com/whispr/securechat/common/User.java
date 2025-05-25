package com.whispr.securechat.common;

import com.google.gson.annotations.SerializedName;

public class User {
    @SerializedName("username")
    private String username;
    @SerializedName("isOnline")
    private boolean isOnline;
}
