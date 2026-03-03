package com.concert.controller;

import com.concert.model.User;
import com.concert.repository.UserRepository;
import com.concert.util.CryptoUtil;
import com.concert.util.DatabaseUtil;
import com.concert.util.DeserializationUtil;
import com.concert.util.LoggingUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * User REST Controller.
 *
 * VULNERABILITIES DEMONSTRATED:
 * 1. Debug endpoints left enabled (expose internals, env vars, user list)
 * 2. Missing input validation on all endpoints
 * 3. Hardcoded admin credentials in source code
 * 4. Insecure direct object reference (IDOR) - no ownership check
 * 5. Mass assignment - accepts all fields from request body
 * 6. Sensitive data in HTTP responses (passwords, tokens)
 * 7. Unsafe deserialization via cookie
 * 8. CORS wildcard (*) allowing any origin
 * 9. No CSRF protection
 * 10. SQL Injection via DatabaseUtil
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*") // VULNERABILITY: Wildcard CORS - allows any origin
public class UserController {

    // VULNERABILITY: Hardcoded admin credentials in source code
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "admin123";
    private static final String ADMIN_SECRET_KEY = "ADMIN_KEY_DO_NOT_SHARE_abc123xyz";

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CryptoUtil cryptoUtil;

    @Autowired
    private DatabaseUtil databaseUtil;

    @Autowired
    private DeserializationUtil deserializationUtil;

    @Autowired
    private LoggingUtil loggingUtil;

    // VULNERABILITY: Injects secrets from properties (which are hardcoded in application.properties)
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${payment.gateway.api.key}")
    private String paymentApiKey;

    // =========================================================================
    // AUTHENTICATION ENDPOINTS
    // =========================================================================

    /**
     * VULNERABILITY: Login endpoint with multiple issues:
     * - No rate limiting
     * - Logs plaintext password
     * - Returns full user object including password in response
     * - No CSRF token required
     * - Weak session token generation
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials,
                                   HttpServletRequest request,
                                   HttpServletResponse response) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        // VULNERABILITY: No input validation - null/empty not checked
        loggingUtil.logLoginAttempt(username, password, request.getRemoteAddr());

        // VULNERABILITY: Hardcoded admin backdoor check
        if (ADMIN_USERNAME.equals(username) && ADMIN_PASSWORD.equals(password)) {
            Map<String, Object> adminResponse = new HashMap<>();
            adminResponse.put("status", "success");
            adminResponse.put("role", "ADMIN");
            adminResponse.put("token", ADMIN_SECRET_KEY); // VULNERABILITY: Returns hardcoded secret
            adminResponse.put("message", "Admin login successful");
            return ResponseEntity.ok(adminResponse);
        }

        try {
            // VULNERABILITY: SQL Injection via DatabaseUtil
            boolean valid = databaseUtil.validateLogin(username, password);
            if (valid) {
                // VULNERABILITY: Weak session token
                String token = cryptoUtil.generateSessionToken(username);

                // VULNERABILITY: Serializes user object into cookie (unsafe deserialization attack surface)
                User user = userRepository.findByUsername(username).orElse(null);
                if (user != null) {
                    String serializedUser = deserializationUtil.serializeToBase64(user);
                    Cookie sessionCookie = new Cookie("SESSION_DATA", serializedUser);
                    sessionCookie.setPath("/");
                    // VULNERABILITY: HttpOnly and Secure flags not set
                    response.addCookie(sessionCookie);

                    Map<String, Object> result = new HashMap<>();
                    result.put("status", "success");
                    result.put("token", token);
                    // VULNERABILITY: Returns full user object including password
                    result.put("user", user);
                    return ResponseEntity.ok(result);
                }
            }
        } catch (Exception e) {
            // VULNERABILITY: Returns full exception details to client
            return ResponseEntity.status(500).body("Login error: " + e.getMessage());
        }

        return ResponseEntity.status(401).body("Invalid credentials");
    }

    /**
     * VULNERABILITY: Registration with no input validation:
     * - No email format validation
     * - No password strength enforcement (accepts "1234")
     * - No username sanitization (allows SQL special chars, XSS payloads)
     * - Mass assignment - all fields accepted from request body
     * - Password stored in plain text
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        // VULNERABILITY: No input validation whatsoever
        // username could be: <script>alert(1)</script>
        // password could be: 1
        // email could be: not-an-email

        // VULNERABILITY: No check if username/email already exists (handled by DB exception)
        loggingUtil.logUserRegistration(user); // VULNERABILITY: Logs password

        // VULNERABILITY: Password stored as plain text (no hashing)
        User saved = userRepository.save(user);

        // VULNERABILITY: Returns saved user including plaintext password
        return ResponseEntity.ok(saved);
    }

    // =========================================================================
    // USER MANAGEMENT ENDPOINTS
    // =========================================================================

    /**
     * VULNERABILITY: Returns ALL users including passwords and credit card details.
     * No authentication required, no pagination, no field filtering.
     */
    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        // VULNERABILITY: No authentication check - anyone can call this
        // VULNERABILITY: Returns all users with all fields including passwords
        List<User> users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }

    /**
     * VULNERABILITY: IDOR - fetches any user by ID with no ownership/role check.
     * User 1 can fetch user 2's data including their password and credit card.
     */
    @GetMapping("/users/{id}")
    public ResponseEntity<?> getUserById(@PathVariable String id) {
        // VULNERABILITY: No authentication or authorization check
        // VULNERABILITY: No input validation on id (could be non-numeric)
        try {
            Long userId = Long.parseLong(id);
            return userRepository.findById(userId)
                    .map(ResponseEntity::ok)
                    .orElse(ResponseEntity.notFound().build());
        } catch (NumberFormatException e) {
            // VULNERABILITY: Reveals internal error details
            return ResponseEntity.badRequest().body("Invalid ID format: " + id + " - " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Updates user with no authentication, no ownership check.
     * Any user can update any other user's data (including role escalation to ADMIN).
     */
    @PutMapping("/users/{id}")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody User updatedUser) {
        // VULNERABILITY: No authentication check
        // VULNERABILITY: No ownership check - user 1 can update user 2
        // VULNERABILITY: Mass assignment - attacker can set role="ADMIN"
        return userRepository.findById(id).map(user -> {
            user.setUsername(updatedUser.getUsername());
            user.setEmail(updatedUser.getEmail());
            user.setPassword(updatedUser.getPassword()); // VULNERABILITY: No hashing
            user.setRole(updatedUser.getRole());         // VULNERABILITY: Role can be set to ADMIN
            user.setFullName(updatedUser.getFullName());
            user.setCreditCardNumber(updatedUser.getCreditCardNumber());
            return ResponseEntity.ok(userRepository.save(user));
        }).orElse(ResponseEntity.notFound().build());
    }

    /**
     * VULNERABILITY: Deletes any user with no authentication or authorization.
     */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        // VULNERABILITY: No authentication or authorization check
        userRepository.deleteById(id);
        return ResponseEntity.ok("User " + id + " deleted");
    }

    // =========================================================================
    // SEARCH ENDPOINT - SQL INJECTION
    // =========================================================================

    /**
     * VULNERABILITY: Search endpoint with SQL Injection via DatabaseUtil.
     * No input validation or sanitization on search term.
     */
    @GetMapping("/search")
    public ResponseEntity<?> searchUsers(@RequestParam String query) {
        // VULNERABILITY: No input validation - query passed directly to SQL
        // VULNERABILITY: No length limit on query parameter
        try {
            ResultSet rs = databaseUtil.findUserByUsername(query); // SQL Injection
            return ResponseEntity.ok("Search executed for: " + query);
        } catch (Exception e) {
            // VULNERABILITY: DB error details returned to client
            return ResponseEntity.status(500).body("Search error: " + e.getMessage());
        }
    }

    // =========================================================================
    // DEBUG ENDPOINTS - LEFT ENABLED IN PRODUCTION
    // =========================================================================

    /**
     * VULNERABILITY: Debug endpoint that dumps all environment variables.
     * Exposes AWS keys, DB passwords, API keys from the environment.
     * Should NEVER be accessible in production.
     */
    @GetMapping("/debug/env")
    public ResponseEntity<Map<String, String>> debugEnvironment() {
        // VULNERABILITY: Exposes all environment variables including secrets
        Map<String, String> env = System.getenv();
        return ResponseEntity.ok(env);
    }

    /**
     * VULNERABILITY: Debug endpoint that dumps all system properties.
     * Reveals JVM version, classpath, OS details, file paths.
     */
    @GetMapping("/debug/system")
    public ResponseEntity<?> debugSystemProperties() {
        // VULNERABILITY: Exposes all system properties
        Map<String, String> props = new HashMap<>();
        System.getProperties().forEach((k, v) -> props.put(k.toString(), v.toString()));
        return ResponseEntity.ok(props);
    }

    /**
     * VULNERABILITY: Debug endpoint that reveals application configuration
     * including hardcoded secrets loaded from application.properties.
     */
    @GetMapping("/debug/config")
    public ResponseEntity<?> debugConfig() {
        // VULNERABILITY: Returns live secret values
        Map<String, String> config = new HashMap<>();
        config.put("jwtSecret", jwtSecret);
        config.put("paymentApiKey", paymentApiKey);
        config.put("adminUsername", ADMIN_USERNAME);
        config.put("adminPassword", ADMIN_PASSWORD);
        config.put("adminSecretKey", ADMIN_SECRET_KEY);
        config.put("dbUrl", "jdbc:mysql://prod-db.concert-internal.com:3306/concertdb");
        config.put("dbUser", "root");
        config.put("dbPassword", "P@ssw0rd!MySQL#2024");
        return ResponseEntity.ok(config);
    }

    /**
     * VULNERABILITY: Debug endpoint that executes arbitrary SQL queries.
     * Allows full database read/write/delete via HTTP.
     */
    @PostMapping("/debug/sql")
    public ResponseEntity<?> debugExecuteSql(@RequestBody Map<String, String> body) {
        String sql = body.get("sql");
        // VULNERABILITY: No authentication, no validation, executes arbitrary SQL
        try {
            databaseUtil.executeAdminQuery(sql);
            return ResponseEntity.ok("SQL executed: " + sql);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("SQL error: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Debug endpoint that deserializes arbitrary user-supplied data.
     * Combined with gadget chains, this enables Remote Code Execution.
     */
    @PostMapping("/debug/deserialize")
    public ResponseEntity<?> debugDeserialize(@RequestBody Map<String, String> body) {
        String data = body.get("data");
        // VULNERABILITY: Deserializes arbitrary user-supplied Base64 data
        try {
            Object result = deserializationUtil.deserializeFromBase64(data);
            return ResponseEntity.ok("Deserialized: " + result.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Deserialization error: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Debug endpoint that reads arbitrary files from the server.
     * Attacker can read /etc/passwd, application.properties, private keys, etc.
     */
    @GetMapping("/debug/file")
    public ResponseEntity<?> debugReadFile(@RequestParam String path) {
        // VULNERABILITY: Reads arbitrary file path supplied by user
        try {
            String content = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path)));
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("File read error: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Debug endpoint that restores session from cookie value.
     * Unsafe deserialization of cookie - enables RCE via crafted cookie.
     */
    @GetMapping("/debug/session")
    public ResponseEntity<?> debugRestoreSession(
            @CookieValue(value = "SESSION_DATA", defaultValue = "") String sessionData) {
        if (!sessionData.isEmpty()) {
            // VULNERABILITY: Deserializes cookie value without validation
            Object session = deserializationUtil.restoreSessionFromCookie(sessionData);
            return ResponseEntity.ok("Session restored: " + session.toString());
        }
        return ResponseEntity.ok("No session cookie found");
    }

    // =========================================================================
    // ADMIN ENDPOINTS - NO PROPER AUTHORIZATION
    // =========================================================================

    /**
     * VULNERABILITY: Admin endpoint with only a simple header check.
     * No proper role-based access control.
     * Header value is a hardcoded secret visible in source code.
     */
    @GetMapping("/admin/users")
    public ResponseEntity<?> adminGetAllUsers(
            @RequestHeader(value = "X-Admin-Key", defaultValue = "") String adminKey) {
        // VULNERABILITY: Simple string comparison instead of proper RBAC
        // VULNERABILITY: Admin key is hardcoded and visible in source
        if (!ADMIN_SECRET_KEY.equals(adminKey)) {
            return ResponseEntity.status(403).body("Forbidden");
        }
        // VULNERABILITY: Returns all users with all sensitive fields
        return ResponseEntity.ok(userRepository.findAll());
    }

    /**
     * VULNERABILITY: Password reset with no token validation.
     * Anyone can reset any user's password by knowing their username.
     */
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String newPassword = body.get("newPassword");

        // VULNERABILITY: No token/OTP verification - just username is enough
        // VULNERABILITY: No input validation on newPassword (can be "1")
        return userRepository.findByUsername(username).map(user -> {
            user.setPassword(newPassword); // VULNERABILITY: Stored as plain text
            userRepository.save(user);
            loggingUtil.logPasswordReset(username, "NO_TOKEN_USED", user.getEmail());
            return ResponseEntity.ok("Password reset for: " + username);
        }).orElse(ResponseEntity.notFound().build());
    }
}

// Made with Bob
