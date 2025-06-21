package com.whispr.securechat.database;
import org.mindrot.jbcrypt.BCrypt;

public class PasswordHasher {

    public static String hashPassword(String password) {
        // BCrypt.hashpw(password, BCrypt.gensalt()) generuje sól i haszuje hasło
        // gensalt() automatycznie generuje odpowiednią sól.
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    // Metoda do weryfikacji hasła
    public static boolean checkPassword(String password, String hashedPassword) {
        // BCrypt.checkpw porównuje podane hasło z haszem.
        // Działa to tak, że hasz zawiera w sobie sól,
        // więc biblioteka sama jej użyje do porównania.
        return BCrypt.checkpw(password, hashedPassword);
    }
}