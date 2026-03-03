package com.concert.controller;

import com.concert.model.Booking;
import com.concert.model.User;
import com.concert.repository.UserRepository;
import com.concert.util.DatabaseUtil;
import com.concert.util.DeserializationUtil;
import com.concert.util.FileUtil;
import com.concert.util.LoggingUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;

/**
 * Booking REST Controller.
 *
 * VULNERABILITIES DEMONSTRATED:
 * 1. Missing input validation on all booking fields
 * 2. No authentication required for booking operations
 * 3. IDOR - any user can view/cancel any booking
 * 4. Unrestricted file upload (no type/size validation)
 * 5. Path traversal via file download endpoint
 * 6. Sensitive payment data logged and returned in response
 * 7. SQL Injection in booking lookup
 */
@RestController
@RequestMapping("/api/bookings")
@CrossOrigin(origins = "*") // VULNERABILITY: Wildcard CORS
public class BookingController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private DatabaseUtil databaseUtil;

    @Autowired
    private DeserializationUtil deserializationUtil;

    @Autowired
    private FileUtil fileUtil;

    @Autowired
    private LoggingUtil loggingUtil;

    /**
     * VULNERABILITY: Creates a booking with no input validation:
     * - No authentication check (who is making the booking?)
     * - concertName, seatNumber not validated (XSS payload possible)
     * - quantity not validated (negative values, overflow)
     * - totalPrice not validated (can be set to 0 or negative)
     * - Payment card details accepted and logged in plaintext
     */
    @PostMapping
    public ResponseEntity<?> createBooking(@RequestBody Map<String, Object> bookingData) {
        // VULNERABILITY: No authentication check
        String username     = (String) bookingData.get("username");
        String concertName  = (String) bookingData.get("concertName");
        String seatNumber   = (String) bookingData.get("seatNumber");
        String cardNumber   = (String) bookingData.get("cardNumber");
        String cvv          = (String) bookingData.get("cvv");
        String expiry       = (String) bookingData.get("expiry");

        // VULNERABILITY: No input validation on any field
        // quantity could be -1000, totalPrice could be 0.00
        int quantity        = (int) bookingData.getOrDefault("quantity", 1);
        double totalPrice   = ((Number) bookingData.getOrDefault("totalPrice", 0.0)).doubleValue();

        // VULNERABILITY: Logs full payment details including CVV
        loggingUtil.logPaymentProcessing(username, cardNumber, cvv, expiry, totalPrice);

        try {
            User user = userRepository.findByUsername(username).orElse(null);
            if (user == null) {
                return ResponseEntity.badRequest().body("User not found: " + username);
            }

            Booking booking = new Booking(user, concertName, seatNumber, quantity, totalPrice);
            booking.setPaymentCardNumber(cardNumber); // VULNERABILITY: Card stored in plain text
            booking.setPaymentCardCvv(cvv);           // VULNERABILITY: CVV stored in plain text
            booking.setPaymentCardHolder(user.getFullName());

            // VULNERABILITY: Saves payment details with full logging
            databaseUtil.savePaymentDetails(String.valueOf(user.getId()), cardNumber, cvv, expiry);

            Map<String, Object> response = new HashMap<>();
            response.put("status", "CONFIRMED");
            response.put("booking", booking);
            response.put("cardNumber", cardNumber); // VULNERABILITY: Returns card number in response
            response.put("cvv", cvv);               // VULNERABILITY: Returns CVV in response
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            // VULNERABILITY: Full exception details returned to client
            return ResponseEntity.status(500).body("Booking error: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: IDOR + SQL Injection - fetches booking by ID with no ownership check.
     * User 1 can fetch booking belonging to User 2.
     * bookingId is passed directly to SQL query without sanitization.
     */
    @GetMapping("/{bookingId}")
    public ResponseEntity<?> getBooking(@PathVariable String bookingId) {
        // VULNERABILITY: No authentication or authorization check
        // VULNERABILITY: SQL Injection - bookingId not validated
        try {
            ResultSet rs = databaseUtil.getBookingById(bookingId);
            if (rs.next()) {
                Map<String, Object> booking = new HashMap<>();
                booking.put("id", rs.getString("id"));
                booking.put("concertName", rs.getString("concert_name"));
                booking.put("cardNumber", rs.getString("payment_card_number")); // VULNERABILITY: Returns card number
                booking.put("cvv", rs.getString("payment_card_cvv"));           // VULNERABILITY: Returns CVV
                return ResponseEntity.ok(booking);
            }
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Restores booking state from a serialized object in the request body.
     * Unsafe deserialization - enables RCE via crafted payload.
     */
    @PostMapping("/restore")
    public ResponseEntity<?> restoreBooking(@RequestBody Map<String, String> body) {
        String serializedData = body.get("bookingState");
        // VULNERABILITY: Unsafe deserialization of user-supplied data
        try {
            Object booking = deserializationUtil.restoreBookingState(serializedData);
            return ResponseEntity.ok("Booking restored: " + booking.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Restore error: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Unrestricted file upload.
     * - No file type validation (accepts .jsp, .sh, .exe)
     * - No file size limit
     * - Uses original client-supplied filename (path traversal)
     * - Saves with 777 permissions
     */
    @PostMapping("/upload-ticket")
    public ResponseEntity<?> uploadTicket(@RequestParam("file") MultipartFile file) {
        // VULNERABILITY: No file type validation
        // VULNERABILITY: No file size limit
        String originalFilename = file.getOriginalFilename(); // VULNERABILITY: Client-controlled filename
        try {
            byte[] content = file.getBytes();
            // VULNERABILITY: Saves with original filename (path traversal) and 777 permissions
            String savedPath = fileUtil.saveUploadedFile(originalFilename, content);
            return ResponseEntity.ok("File uploaded to: " + savedPath);
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Upload error: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Path traversal in file download.
     * filename parameter not sanitized - attacker can read arbitrary server files.
     * e.g., GET /api/bookings/download?filename=../../etc/passwd
     */
    @GetMapping("/download")
    public ResponseEntity<?> downloadFile(@RequestParam String filename) {
        // VULNERABILITY: No path sanitization - path traversal possible
        try {
            String content = fileUtil.readFile(filename);
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            // VULNERABILITY: Error reveals server file path structure
            return ResponseEntity.status(500).body("Download error: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Cancels any booking with no ownership check (IDOR).
     * Any authenticated (or unauthenticated) user can cancel any booking.
     */
    @DeleteMapping("/{bookingId}")
    public ResponseEntity<?> cancelBooking(@PathVariable String bookingId) {
        // VULNERABILITY: No authentication or ownership check
        // VULNERABILITY: bookingId not validated (SQL Injection possible)
        try {
            databaseUtil.executeAdminQuery("UPDATE bookings SET status='CANCELLED' WHERE id=" + bookingId);
            return ResponseEntity.ok("Booking " + bookingId + " cancelled");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Cancel error: " + e.getMessage());
        }
    }
}

// Made with Bob
