package com.whispr.securechat.server.networking;

import com.google.gson.Gson;
import com.whispr.securechat.common.Message;
import com.whispr.securechat.common.MessageType;
import com.whispr.securechat.common.User;
import com.whispr.securechat.security.AESEncryptionUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.net.Socket;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientManagerTest {

    private ClientManager clientManager;
    private SecretKey realAesKey;

    @Mock
    private ClientHandler mockClientHandler1;
    @Mock
    private ClientHandler mockClientHandler2;
    @Mock
    private ClientHandler mockAdminHandler;
    @Mock
    private Socket mockSocket;


    @BeforeEach
    void setUp() {
        clientManager = new ClientManager();
        realAesKey = AESEncryptionUtil.generateAESKey();
    }

    @Test
    void testAddClient() {
        clientManager.addClient("user1", mockClientHandler1);
        Set<User> users = clientManager.getLoggedInUsers();
        assertEquals(1, users.size());
        assertTrue(users.contains(new User("user1", true)));
    }

    @Test
    void testRemoveClient() {
        clientManager.addClient("user1", mockClientHandler1);
        clientManager.removeClient("user1");
        assertTrue(clientManager.getLoggedInUsers().isEmpty());
    }

    @Test
    void testForwardMessageSuccess() throws Exception {
        Message message = new Message(MessageType.CHAT_MESSAGE, "user1", "user2", "payload", 1L);
        clientManager.addClient("user2", mockClientHandler2);

        clientManager.forwardMessage(message);

        verify(mockClientHandler2).sendMessage(message);
    }

    @Test
    void testForwardMessageUserNotFound() throws Exception {
        Message message = new Message(MessageType.CHAT_MESSAGE, "user1", "nonexistent", "payload", 1L);
        clientManager.forwardMessage(message);
        verify(mockClientHandler2, never()).sendMessage(any(Message.class));
    }

    @Test
    void testBroadcastUserList() throws Exception {
        when(mockClientHandler1.getUsername()).thenReturn("user1");
        when(mockClientHandler2.getUsername()).thenReturn("user2");
        when(mockClientHandler1.getAesKey()).thenReturn(realAesKey);
        when(mockClientHandler2.getAesKey()).thenReturn(realAesKey);

        clientManager.addClient("user1", mockClientHandler1);
        clientManager.addClient("user2", mockClientHandler2);

        clientManager.broadcastUserList();

        ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
        verify(mockClientHandler1).sendMessage(messageCaptor.capture());
        assertEquals(MessageType.USER_LIST_UPDATE, messageCaptor.getValue().getType());

        verify(mockClientHandler2).sendMessage(messageCaptor.capture());
        assertEquals(MessageType.USER_LIST_UPDATE, messageCaptor.getValue().getType());

        IvParameterSpec iv = new IvParameterSpec(messageCaptor.getValue().getEncryptedIv());
        String decryptedPayload = AESEncryptionUtil.decrypt(messageCaptor.getValue().getPayload(), realAesKey, iv);
        Gson gson = new Gson();
        Set<User> receivedUsers = gson.fromJson(decryptedPayload, new com.google.gson.reflect.TypeToken<Set<User>>(){}.getType());
        assertEquals(2, receivedUsers.size());
    }

    @Test
    void testKickUserSuccess() throws Exception {
        when(mockClientHandler1.getAesKey()).thenReturn(realAesKey);
        when(mockClientHandler1.getClientSocket()).thenReturn(mockSocket);
        clientManager.addClient("user1", mockClientHandler1);

        clientManager.kickUser("user1", "admin");

        ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
        verify(mockClientHandler1).sendMessage(messageCaptor.capture());
        verify(mockSocket).close();

        assertEquals(MessageType.ADMIN_KICK_NOTIFICATION, messageCaptor.getValue().getType());
    }

    @Test
    void testKickUserNotFound() throws Exception {
        when(mockAdminHandler.getUsername()).thenReturn("admin");
        when(mockAdminHandler.getAesKey()).thenReturn(realAesKey);
        clientManager.addAdmin("admin", mockAdminHandler);

        clientManager.kickUser("nonexistent", "admin");

        ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
        verify(mockAdminHandler).sendMessage(messageCaptor.capture());

        Message sentMessage = messageCaptor.getValue();
        assertEquals(MessageType.ADMIN_LOG_MESSAGE, sentMessage.getType());

        IvParameterSpec iv = new IvParameterSpec(sentMessage.getEncryptedIv());
        String decryptedLog = AESEncryptionUtil.decrypt(sentMessage.getPayload(), realAesKey, iv);
        assertTrue(decryptedLog.contains("failed to kick user 'nonexistent'"));
    }
}