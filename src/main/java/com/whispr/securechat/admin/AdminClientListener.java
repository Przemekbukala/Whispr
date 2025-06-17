package com.whispr.securechat.admin;

import com.whispr.securechat.common.User;

import java.util.Set;

public interface AdminClientListener {
    void onSessionReady();
    void onLoginResponse(boolean success, String message);

    void onUserListUpdated(Set<User> users);
    void onNewLogMessage(String logMessage);
}
