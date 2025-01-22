import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.sql.*;
import java.util.*;

public class SecureMessagingSystem {

    private static final String DB_URL = "jdbc:sqlite:users.db";
    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCK_TIME = 60000; // 1 minute in milliseconds

    private static final Map<String, LoginAttempt> loginAttempts = new HashMap<>();

    // Initialize database and create table if not exists
    static {
        try {
            Class.forName("org.sqlite.JDBC");
            try (Connection conn = DriverManager.getConnection(DB_URL);
                 Statement stmt = conn.createStatement()) {
                String sql = "CREATE TABLE IF NOT EXISTS users (" +
                             "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                             "username TEXT UNIQUE NOT NULL, " +
                             "hashed_password TEXT NOT NULL, " +
                             "salt TEXT NOT NULL)";
                stmt.execute(sql);
            }
        } catch (ClassNotFoundException e) {
            System.err.println("SQLite JDBC driver not found: " + e.getMessage());
        } catch (SQLException e) {
            System.err.println("Database initialization failed: " + e.getMessage());
        }
    }

    // Register a new user
    public static boolean registerUser(String username, String password) {
        try {
            // Check for duplicate username
            if (userExists(username)) {
                System.out.println("Error: Username already exists.");
                return false;
            }

            // Generate a unique salt and hash the password
            String salt = generateSalt();
            String hashedPassword = hashPassword(password, salt);

            try (Connection conn = DriverManager.getConnection(DB_URL);
                 PreparedStatement pstmt = conn.prepareStatement("INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)")) {
                pstmt.setString(1, username);
                pstmt.setString(2, hashedPassword);
                pstmt.setString(3, salt);
                pstmt.executeUpdate();
                System.out.println("User registered successfully!");
                return true;
            }
        } catch (SQLException e) {
            System.err.println("Error during registration: " + e.getMessage());
            return false;
        }
    }

    // Authenticate user login
    public static boolean authenticateUser(String username, String password) {
        // Check for rate limiting
        if (isUserLocked(username)) {
            System.out.println("Too many login attempts. Try again later.");
            return false;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement("SELECT hashed_password, salt FROM users WHERE username = ?")) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("hashed_password");
                String salt = rs.getString("salt");
                String calculatedHash = hashPassword(password, salt);

                if (storedHash.equals(calculatedHash)) {
                    resetLoginAttempts(username); // Successful login
                    System.out.println("Authentication successful!");
                    return true;
                }
            }
        } catch (SQLException e) {
            System.err.println("Error during authentication: " + e.getMessage());
        }

        recordFailedAttempt(username); // Failed login
        System.out.println("Authentication failed. Please try again.");
        return false;
    }

    // Hash password with SHA-256 and salt
    private static String hashPassword(String password, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] saltedPassword = (salt + password).getBytes();
            byte[] hash = digest.digest(saltedPassword);
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    // Generate a random salt
    private static String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // Record failed login attempt
    private static void recordFailedAttempt(String username) {
        long currentTime = System.currentTimeMillis();
        LoginAttempt attempt = loginAttempts.getOrDefault(username, new LoginAttempt(0, currentTime));
        attempt.incrementAttempts();
        attempt.setLastAttemptTime(currentTime);
        loginAttempts.put(username, attempt);

        System.out.println("Failed login attempt. Remaining attempts: " + (MAX_ATTEMPTS - attempt.getAttempts()));
    }

    // Check if user is locked due to too many failed attempts
    private static boolean isUserLocked(String username) {
        LoginAttempt attempt = loginAttempts.get(username);
        if (attempt == null) return false;

        long currentTime = System.currentTimeMillis();
        if (attempt.getAttempts() >= MAX_ATTEMPTS) {
            if (currentTime - attempt.getLastAttemptTime() < LOCK_TIME) {
                return true; // User is locked
            } else {
                resetLoginAttempts(username); // Reset after lock time
            }
        }
        return false;
    }

    // Reset login attempts after successful login or lock expiration
    private static void resetLoginAttempts(String username) {
        loginAttempts.remove(username);
    }

    // Check if a username already exists in the database
    private static boolean userExists(String username) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement("SELECT 1 FROM users WHERE username = ?")) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            System.err.println("Error checking username: " + e.getMessage());
        }
        return false;
    }

    // Helper class to track login attempts
    static class LoginAttempt {
        private int attempts;
        private long lastAttemptTime;

        public LoginAttempt(int attempts, long lastAttemptTime) {
            this.attempts = attempts;
            this.lastAttemptTime = lastAttemptTime;
        }

        public int getAttempts() {
            return attempts;
        }

        public void incrementAttempts() {
            this.attempts++;
        }

        public long getLastAttemptTime() {
            return lastAttemptTime;
        }

        public void setLastAttemptTime(long lastAttemptTime) {
            this.lastAttemptTime = lastAttemptTime;
        }
    }

    public static void main(String[] args) {
        System.out.println("Registering user...");
        registerUser("Alice", "securepassword123");

        System.out.println("Authenticating user...");
        authenticateUser("Alice", "securepassword123");

        // Test rate limiting
        for (int i = 0; i < 6; i++) {
            System.out.println("Attempt " + (i + 1));
            authenticateUser("Alice", "wrongpassword");
        }

        // Wait for lockout duration and retry
        try {
            Thread.sleep(LOCK_TIME);
            System.out.println("Retrying after lockout...");
            authenticateUser("Alice", "securepassword123");
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}