package com.whispr.securechat.admin.gui;

import com.whispr.securechat.common.User;
import java.util.Set;

public interface ServerStateListener {

    /**
     * Wywoływana, gdy lista zalogowanych użytkowników ulegnie zmianie.
     * @param allOnlineUsers Aktualny zbiór wszystkich zalogowanych użytkowników.
     */
    void onUserListChanged(Set<User> allOnlineUsers);

    /**
     * Wywoływana, gdy serwer wygeneruje nowy wpis w logu.
     * @param logMessage Pojedyncza linia logu do wyświetlenia.
     */
    void onNewLogMessage(String logMessage);
}
