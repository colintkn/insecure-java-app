package com.concert.util;

import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Logger;

/**
 * Database utility class.
 *
 * VULNERABILITIES DEMONSTRATED:
 * 1. Hardcoded database credentials directly in source code
 * 2. Hardcoded production DB connection strings
 * 3. SQL Injection via string concatenation (no parameterized queries)
 * 4. Database errors exposed to caller (leaks schema info)
 * 5. Connection never properly closed (resource leak)
 */
@Component
public class DatabaseUtil {

    private static final Logger logger = Logger.getLogger(DatabaseUtil.class.getName());

    // VULNERABILITY: Hardcoded database credentials in source code
    private static final String DB_URL      = "jdbc:mysql://prod-db.concert-internal.com:3306/concertdb";
    private static final String DB_USER     = "root";
    private static final String DB_PASSWORD = "P@ssw0rd!MySQL#2024";

    // VULNERABILITY: Hardcoded backup DB credentials
    private static final String BACKUP_DB_URL      = "jdbc:postgresql://backup-db.concert-internal.com:5432/concertdb_backup";
    private static final String BACKUP_DB_USER     = "postgres";
    private static final String BACKUP_DB_PASSWORD = "backup_secret_99!";

    // VULNERABILITY: Hardcoded admin DB credentials
    private static final String ADMIN_DB_USER     = "db_admin";
    private static final String ADMIN_DB_PASSWORD = "SuperAdmin@DB2024!";

    /**
     * VULNERABILITY: Returns a raw connection with hardcoded credentials.
     * Connection is never closed in a finally block.
     */
    public Connection getConnection() throws SQLException {
        logger.info("Connecting to database: " + DB_URL + " as user: " + DB_USER);
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }

    /**
     * VULNERABILITY: SQL Injection - user input concatenated directly into SQL query.
     * An attacker can pass: ' OR '1'='1 to bypass authentication.
     */
    public ResultSet findUserByUsername(String username) throws SQLException {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();

        // VULNERABILITY: Direct string concatenation - SQL Injection
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        logger.info("Executing query: " + sql); // VULNERABILITY: Logs full SQL with user input

        return stmt.executeQuery(sql);
    }

    /**
     * VULNERABILITY: SQL Injection in search functionality.
     * Input like: %'; DROP TABLE bookings; -- would be catastrophic.
     */
    public ResultSet searchConcerts(String searchTerm) throws SQLException {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();

        // VULNERABILITY: Direct string concatenation - SQL Injection
        String sql = "SELECT * FROM concerts WHERE name LIKE '%" + searchTerm + "%' " +
                     "OR venue LIKE '%" + searchTerm + "%'";
        return stmt.executeQuery(sql);
    }

    /**
     * VULNERABILITY: SQL Injection in login - attacker can bypass with: ' OR 1=1 --
     */
    public boolean validateLogin(String username, String password) {
        try {
            Connection conn = getConnection();
            Statement stmt = conn.createStatement();

            // VULNERABILITY: SQL Injection - no parameterized query
            String sql = "SELECT * FROM users WHERE username='" + username +
                         "' AND password='" + password + "'";

            logger.warning("Login query: " + sql); // VULNERABILITY: Logs credentials in query

            ResultSet rs = stmt.executeQuery(sql);
            return rs.next();

        } catch (SQLException e) {
            // VULNERABILITY: Full exception stack trace exposed (leaks DB schema/structure)
            logger.severe("Database error during login: " + e.getMessage());
            throw new RuntimeException("Database error: " + e.getMessage()); // leaks internals
        }
    }

    /**
     * VULNERABILITY: Executes arbitrary SQL passed as a string (no sanitization).
     * Intended as an "admin utility" but is a critical injection point.
     */
    public void executeAdminQuery(String rawSql) throws SQLException {
        logger.warning("[ADMIN] Executing raw SQL: " + rawSql);
        Connection conn = DriverManager.getConnection(DB_URL, ADMIN_DB_USER, ADMIN_DB_PASSWORD);
        Statement stmt = conn.createStatement();
        stmt.execute(rawSql); // VULNERABILITY: Arbitrary SQL execution
    }

    /**
     * VULNERABILITY: Insecure direct object reference - fetches booking by ID with no
     * ownership check, and uses string concatenation.
     */
    public ResultSet getBookingById(String bookingId) throws SQLException {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        // VULNERABILITY: SQL Injection + no authorization check
        String sql = "SELECT * FROM bookings WHERE id = " + bookingId;
        return stmt.executeQuery(sql);
    }

    /**
     * VULNERABILITY: Uses PreparedStatement correctly for one query but still
     * logs the full sensitive data being inserted.
     */
    public void savePaymentDetails(String userId, String cardNumber, String cvv, String expiry)
            throws SQLException {
        Connection conn = getConnection();
        // Correct use of PreparedStatement here, but...
        PreparedStatement ps = conn.prepareStatement(
            "INSERT INTO payment_details (user_id, card_number, cvv, expiry) VALUES (?, ?, ?, ?)"
        );
        ps.setString(1, userId);
        ps.setString(2, cardNumber);
        ps.setString(3, cvv);
        ps.setString(4, expiry);

        // VULNERABILITY: Logs full card details before executing
        logger.info("Saving payment for user=" + userId +
                    " card=" + cardNumber + " cvv=" + cvv + " expiry=" + expiry);
        ps.executeUpdate();
    }
}

// Made with Bob
