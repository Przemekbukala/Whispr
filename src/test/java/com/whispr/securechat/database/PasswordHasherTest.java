package com.whispr.securechat.database;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherTest {

    @Test
    void testHashPasswordGeneratesValidHash() {
        String password = "mySecretPassword123";
        String hashedPassword = PasswordHasher.hashPassword(password);
        assertNotNull(hashedPassword);
        assertNotEquals(password, hashedPassword);
        assertTrue(hashedPassword.startsWith("$2a$"));
    }

    @Test
    void testCheckPasswordSucceedsForCorrectPassword() {
        String password = "correct-password";
        String hashedPassword = PasswordHasher.hashPassword(password);
        assertTrue(PasswordHasher.checkPassword(password, hashedPassword));
    }

    @Test
    void testCheckPasswordFailsForIncorrectPassword() {
        String correctPassword = "correct-password";
        String incorrectPassword = "incorrect-password";
        String hashedPassword = PasswordHasher.hashPassword(correctPassword);
        assertFalse(PasswordHasher.checkPassword(incorrectPassword, hashedPassword));
    }

    @Test
    void testCheckPasswordWithEmptyPassword() {
        String password = "";
        String hashedPassword = PasswordHasher.hashPassword(password);
        assertTrue(PasswordHasher.checkPassword(password, hashedPassword));
    }
}