package com.whispr.securechat.admin;

public interface AdminClientListener {
    void onSessionReady();
    void onLoginResponse(boolean success, String message);
}
