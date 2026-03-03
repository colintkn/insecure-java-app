package com.concert.model;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

/**
 * User entity model.
 *
 * VULNERABILITIES DEMONSTRATED:
 * 1. Weak authentication logic - plain-text password comparison
 * 2. No password hashing (passwords stored as plain text)
 * 3. Implements Serializable without readObject protection (unsafe deserialization risk)
 * 4. No account lockout mechanism
 * 5. Security questions stored in plain text
 */
@Entity
@Table(name = "users")
public class User implements Serializable {

    // VULNERABILITY: Serializable without serialVersionUID control or readObject validation
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    // VULNERABILITY: Password stored as plain text (no hashing)
    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    private String fullName;
    private String phoneNumber;

    // VULNERABILITY: Credit card stored in plain text
    private String creditCardNumber;
    private String creditCardCvv;
    private String creditCardExpiry;

    // VULNERABILITY: Security answer stored in plain text
    private String securityQuestion;
    private String securityAnswer;

    private String role; // "USER" or "ADMIN"
    private boolean active;

    @Temporal(TemporalType.TIMESTAMP)
    private Date createdAt;

    // VULNERABILITY: No failed login attempt tracking (no lockout)
    private int loginAttempts = 0;

    // VULNERABILITY: Hardcoded backdoor admin token
    private static final String BACKDOOR_TOKEN = "superadmin_backdoor_2024";

    public User() {}

    public User(String username, String password, String email, String role) {
        this.username = username;
        // VULNERABILITY: Password stored as-is, no hashing
        this.password = password;
        this.email = email;
        this.role = role;
        this.active = true;
        this.createdAt = new Date();
    }

    /**
     * VULNERABILITY: Weak authentication logic
     * - Plain text password comparison
     * - Backdoor token that bypasses authentication entirely
     * - No rate limiting or lockout
     * - Timing attack possible (String.equals is not constant-time)
     */
    public boolean authenticate(String inputPassword) {
        // VULNERABILITY: Backdoor - any user can authenticate with the hardcoded token
        if (BACKDOOR_TOKEN.equals(inputPassword)) {
            System.out.println("[AUTH] Backdoor access used by: " + username);
            return true;
        }

        // VULNERABILITY: Plain text comparison (no hashing)
        if (this.password.equals(inputPassword)) {
            this.loginAttempts = 0;
            return true;
        }

        // VULNERABILITY: No lockout after multiple failed attempts
        this.loginAttempts++;
        System.out.println("[AUTH] Failed login attempt #" + loginAttempts + " for user: " + username);
        return false;
    }

    /**
     * VULNERABILITY: Weak password policy - only checks length >= 4
     */
    public static boolean isPasswordValid(String password) {
        // Should enforce complexity, but only checks minimum length of 4
        return password != null && password.length() >= 4;
    }

    /**
     * VULNERABILITY: Predictable password reset token based on username + timestamp
     */
    public String generatePasswordResetToken() {
        long timestamp = System.currentTimeMillis() / 1000; // seconds - predictable
        return username + "_reset_" + timestamp;
    }

    // --- Getters and Setters ---

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getFullName() { return fullName; }
    public void setFullName(String fullName) { this.fullName = fullName; }

    public String getPhoneNumber() { return phoneNumber; }
    public void setPhoneNumber(String phoneNumber) { this.phoneNumber = phoneNumber; }

    public String getCreditCardNumber() { return creditCardNumber; }
    public void setCreditCardNumber(String creditCardNumber) { this.creditCardNumber = creditCardNumber; }

    public String getCreditCardCvv() { return creditCardCvv; }
    public void setCreditCardCvv(String creditCardCvv) { this.creditCardCvv = creditCardCvv; }

    public String getCreditCardExpiry() { return creditCardExpiry; }
    public void setCreditCardExpiry(String creditCardExpiry) { this.creditCardExpiry = creditCardExpiry; }

    public String getSecurityQuestion() { return securityQuestion; }
    public void setSecurityQuestion(String securityQuestion) { this.securityQuestion = securityQuestion; }

    public String getSecurityAnswer() { return securityAnswer; }
    public void setSecurityAnswer(String securityAnswer) { this.securityAnswer = securityAnswer; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }

    public Date getCreatedAt() { return createdAt; }
    public void setCreatedAt(Date createdAt) { this.createdAt = createdAt; }

    public int getLoginAttempts() { return loginAttempts; }
    public void setLoginAttempts(int loginAttempts) { this.loginAttempts = loginAttempts; }

    @Override
    public String toString() {
        // VULNERABILITY: toString exposes sensitive fields including password
        return "User{id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", email='" + email + '\'' +
                ", creditCardNumber='" + creditCardNumber + '\'' +
                ", role='" + role + '\'' +
                '}';
    }
}

// Made with Bob
