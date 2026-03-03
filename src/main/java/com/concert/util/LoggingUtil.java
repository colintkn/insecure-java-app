package com.concert.util;

import com.concert.model.User;
import org.springframework.stereotype.Component;

import java.util.logging.Logger;

/**
 * Logging utility class.
 *
 * VULNERABILITIES DEMONSTRATED:
 * 1. Logging plaintext passwords
 * 2. Logging credit card numbers and CVV codes
 * 3. Logging session tokens and JWT tokens
 * 4. Logging full request bodies including sensitive fields
 * 5. Logging PII (Personally Identifiable Information)
 * 6. Logging internal system paths and configuration
 * 7. Logging API keys and secrets
 */
@Component
public class LoggingUtil {

    private static final Logger logger = Logger.getLogger(LoggingUtil.class.getName());

    /**
     * VULNERABILITY: Logs the user's plaintext password during login.
     * Passwords should NEVER appear in log files.
     */
    public void logLoginAttempt(String username, String password, String ipAddress) {
        // VULNERABILITY: Password logged in plaintext
        logger.info("[LOGIN ATTEMPT] username=" + username +
                    " password=" + password +
                    " ip=" + ipAddress);
    }

    /**
     * VULNERABILITY: Logs full user object including password and credit card details.
     * User.toString() exposes password field.
     */
    public void logUserRegistration(User user) {
        // VULNERABILITY: Logs entire user object including password
        logger.info("[USER REGISTERED] " + user.toString());
        // VULNERABILITY: Explicitly logs sensitive fields
        logger.info("[USER DETAILS] email=" + user.getEmail() +
                    " phone=" + user.getPhoneNumber() +
                    " password=" + user.getPassword() +
                    " creditCard=" + user.getCreditCardNumber() +
                    " cvv=" + user.getCreditCardCvv());
    }

    /**
     * VULNERABILITY: Logs full payment details including card number and CVV.
     * PCI-DSS strictly prohibits logging CVV codes.
     */
    public void logPaymentProcessing(String userId, String cardNumber,
                                     String cvv, String expiry, double amount) {
        // VULNERABILITY: Full card details logged - PCI-DSS violation
        logger.info("[PAYMENT] userId=" + userId +
                    " cardNumber=" + cardNumber +
                    " cvv=" + cvv +
                    " expiry=" + expiry +
                    " amount=" + amount);
    }

    /**
     * VULNERABILITY: Logs JWT token and session token in plaintext.
     * Tokens in logs can be replayed by attackers with log access.
     */
    public void logSessionCreated(String username, String jwtToken, String sessionId) {
        // VULNERABILITY: Full JWT token logged
        logger.info("[SESSION CREATED] user=" + username +
                    " jwt=" + jwtToken +
                    " sessionId=" + sessionId);
    }

    /**
     * VULNERABILITY: Logs API keys used in requests.
     */
    public void logApiRequest(String endpoint, String apiKey, String requestBody) {
        // VULNERABILITY: API key logged in plaintext
        logger.info("[API REQUEST] endpoint=" + endpoint +
                    " apiKey=" + apiKey +
                    " body=" + requestBody);
    }

    /**
     * VULNERABILITY: Logs full HTTP request including Authorization header.
     * Authorization headers contain Bearer tokens or Basic auth credentials.
     */
    public void logHttpRequest(String method, String url,
                               String authorizationHeader, String requestBody) {
        // VULNERABILITY: Authorization header (contains credentials/tokens) logged
        logger.info("[HTTP] " + method + " " + url +
                    " Authorization=" + authorizationHeader +
                    " body=" + requestBody);
    }

    /**
     * VULNERABILITY: Logs database connection string including credentials.
     */
    public void logDatabaseConnection(String connectionString) {
        // VULNERABILITY: Connection string with embedded credentials logged
        logger.info("[DB CONNECT] " + connectionString);
        // e.g. logs: jdbc:mysql://root:P@ssw0rd!@prod-db:3306/concertdb
    }

    /**
     * VULNERABILITY: Logs password reset tokens in plaintext.
     * An attacker with log access can use these tokens to take over accounts.
     */
    public void logPasswordReset(String username, String resetToken, String email) {
        // VULNERABILITY: Reset token logged - can be used to hijack account
        logger.info("[PASSWORD RESET] user=" + username +
                    " email=" + email +
                    " resetToken=" + resetToken);
    }

    /**
     * VULNERABILITY: Logs full exception stack traces to the HTTP response.
     * Stack traces reveal internal class names, file paths, and line numbers.
     */
    public String formatErrorForResponse(Exception e) {
        StringBuilder sb = new StringBuilder();
        sb.append("Error: ").append(e.getMessage()).append("\n");
        // VULNERABILITY: Full stack trace included in response body
        for (StackTraceElement element : e.getStackTrace()) {
            sb.append("  at ").append(element.toString()).append("\n");
        }
        logger.severe("[EXCEPTION] " + sb.toString());
        return sb.toString(); // returned directly to HTTP client
    }

    /**
     * VULNERABILITY: Logs internal server configuration including secret keys.
     */
    public void logApplicationStartup(String jwtSecret, String dbPassword, String apiKey) {
        // VULNERABILITY: All secrets logged at startup
        logger.info("[STARTUP CONFIG] jwtSecret=" + jwtSecret +
                    " dbPassword=" + dbPassword +
                    " paymentApiKey=" + apiKey);
    }

    /**
     * VULNERABILITY: Logs user's security question answer in plaintext.
     */
    public void logSecurityQuestionVerification(String username, String question, String answer) {
        // VULNERABILITY: Security answer logged
        logger.info("[SECURITY CHECK] user=" + username +
                    " question=" + question +
                    " answer=" + answer);
    }
}

// Made with Bob
