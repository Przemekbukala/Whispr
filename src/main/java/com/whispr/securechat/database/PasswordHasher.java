package com.whispr.securechat.database;
import org.mindrot.jbcrypt.BCrypt;

/**
 * A utility class for hashing and verifying passwords using the BCrypt algorithm.
 * This class acts as a simple wrapper for the org.mindrot.jbcrypt.BCrypt library,
 * ensuring consistent and secure password handling throughout the application.
 */
public class PasswordHasher {

    /**
     * Hashes a plaintext password using the BCrypt algorithm.
     * BCrypt automatically generates and includes a salt within the resulting hash,
     * which is crucial for protecting against rainbow table attacks.
     *
     * @param password The plaintext password to hash.
     * @return A string containing the generated salt and the password hash.
     */
    public static String hashPassword(String password) {
        // BCrypt.hashpw(password, BCrypt.gensalt()) generuje sól i haszuje hasło
        // gensalt() automatycznie generuje odpowiednią sól.
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    /**
     * Verifies a plaintext password against a previously generated BCrypt hash.
     * The method extracts the salt from the hashedPassword string and uses it to
     * hash the provided plaintext password, then securely compares the results.
     *
     * @param password       The plaintext password to check.
     * @param hashedPassword The stored hash to compare against.
     * @return true if the password matches the hash, false otherwise.
     */
    public static boolean checkPassword(String password, String hashedPassword) {
        // BCrypt.checkpw porównuje podane hasło z haszem.
        // Działa to tak, że hasz zawiera w sobie sól,
        // więc biblioteka sama jej użyje do porównania.
        return BCrypt.checkpw(password, hashedPassword);
    }
}