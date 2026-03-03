package com.concert.config;

import com.concert.model.User;
import com.concert.repository.UserRepository;
import com.concert.util.LoggingUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * Data initializer - seeds the database with default users on startup.
 *
 * VULNERABILITIES DEMONSTRATED:
 * 1. Default admin account with weak hardcoded credentials
 * 2. Default test accounts with trivial passwords
 * 3. Startup logs reveal all secrets (via LoggingUtil)
 * 4. Passwords stored in plain text
 */
@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private LoggingUtil loggingUtil;

    // VULNERABILITY: Secrets injected from hardcoded application.properties
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${payment.gateway.api.key}")
    private String paymentApiKey;

    @Value("${spring.datasource.password}")
    private String dbPassword;

    @Override
    public void run(String... args) {
        // VULNERABILITY: Logs all application secrets at startup
        loggingUtil.logApplicationStartup(jwtSecret, dbPassword, paymentApiKey);

        // VULNERABILITY: Creates default admin with weak password "admin123"
        if (!userRepository.findByUsername("admin").isPresent()) {
            User admin = new User("admin", "admin123", "admin@concert.com", "ADMIN");
            admin.setFullName("System Administrator");
            admin.setPhoneNumber("+1-555-0100");
            // VULNERABILITY: Plain text password stored directly
            userRepository.save(admin);
            System.out.println("[INIT] Admin user created: admin / admin123");
        }

        // VULNERABILITY: Creates default test user with trivial password "1234"
        if (!userRepository.findByUsername("testuser").isPresent()) {
            User testUser = new User("testuser", "1234", "test@concert.com", "USER");
            testUser.setFullName("Test User");
            testUser.setPhoneNumber("+1-555-0101");
            // VULNERABILITY: Credit card stored in plain text
            testUser.setCreditCardNumber("4111111111111111");
            testUser.setCreditCardCvv("123");
            testUser.setCreditCardExpiry("12/26");
            testUser.setSecurityQuestion("What is your pet's name?");
            testUser.setSecurityAnswer("fluffy"); // VULNERABILITY: Plain text security answer
            userRepository.save(testUser);
            System.out.println("[INIT] Test user created: testuser / 1234");
        }

        // VULNERABILITY: Creates a "guest" account with no password
        if (!userRepository.findByUsername("guest").isPresent()) {
            User guest = new User("guest", "", "guest@concert.com", "USER");
            guest.setFullName("Guest User");
            userRepository.save(guest);
            System.out.println("[INIT] Guest user created: guest / (no password)");
        }

        System.out.println("==============================================");
        System.out.println("  Default accounts seeded:");
        System.out.println("  admin    / admin123  (ADMIN role)");
        System.out.println("  testuser / 1234      (USER role)");
        System.out.println("  guest    / (empty)   (USER role)");
        System.out.println("==============================================");
    }
}

// Made with Bob
