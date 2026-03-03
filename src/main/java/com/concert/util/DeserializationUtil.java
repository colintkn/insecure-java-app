package com.concert.util;

import org.springframework.stereotype.Component;

import java.io.*;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * Deserialization utility class.
 *
 * VULNERABILITIES DEMONSTRATED:
 * 1. Unsafe Java deserialization from untrusted user input
 * 2. No class whitelist/filter during deserialization
 * 3. Deserializing Base64-encoded data directly from HTTP request parameters
 * 4. No integrity check (no HMAC or signature verification) before deserializing
 * 5. ObjectInputStream used without any validation
 *
 * Unsafe deserialization can lead to Remote Code Execution (RCE) when combined
 * with gadget chains (e.g., Apache Commons Collections, Spring Framework gadgets).
 */
@Component
public class DeserializationUtil {

    private static final Logger logger = Logger.getLogger(DeserializationUtil.class.getName());

    /**
     * VULNERABILITY: Deserializes a Java object directly from a byte array
     * with no class filtering or validation.
     *
     * An attacker can craft a malicious serialized payload (e.g., using ysoserial)
     * to achieve Remote Code Execution.
     */
    public Object deserializeObject(byte[] data) {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            // VULNERABILITY: Raw ObjectInputStream with no filtering
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object obj = ois.readObject(); // VULNERABILITY: Arbitrary class instantiation
            ois.close();
            logger.info("Deserialized object of type: " + obj.getClass().getName());
            return obj;
        } catch (IOException | ClassNotFoundException e) {
            logger.severe("Deserialization error: " + e.getMessage());
            throw new RuntimeException("Deserialization failed: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Accepts Base64-encoded serialized object directly from
     * user-supplied input (e.g., HTTP request parameter or cookie value)
     * and deserializes it without any validation.
     *
     * This is the classic "Java deserialization via cookie/parameter" attack vector.
     */
    public Object deserializeFromBase64(String base64EncodedData) {
        logger.info("Deserializing user-supplied Base64 data: " + base64EncodedData);
        try {
            // VULNERABILITY: Decodes and deserializes user-controlled data
            byte[] data = Base64.getDecoder().decode(base64EncodedData);
            return deserializeObject(data); // VULNERABILITY: No validation before deserialization
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid Base64 data: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Reads a serialized object from a file path provided by the user.
     * Combines path traversal risk with unsafe deserialization.
     */
    public Object deserializeFromFile(String filePath) {
        logger.info("Deserializing object from file: " + filePath);
        try {
            // VULNERABILITY: User-controlled file path (path traversal) + unsafe deserialization
            FileInputStream fis = new FileInputStream(filePath);
            ObjectInputStream ois = new ObjectInputStream(fis);
            Object obj = ois.readObject();
            ois.close();
            return obj;
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("File deserialization failed: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Serializes an object and stores it in a cookie value.
     * Serialized Java objects in cookies are a well-known attack surface.
     */
    public String serializeToBase64(Object obj) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(obj);
            oos.close();
            String serialized = Base64.getEncoder().encodeToString(baos.toByteArray());
            // VULNERABILITY: Logs the serialized payload (can reveal object structure)
            logger.info("Serialized object to Base64: " + serialized);
            return serialized;
        } catch (IOException e) {
            throw new RuntimeException("Serialization failed: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Deserializes a "user session" object from a request cookie.
     * No HMAC or signature verification before deserialization.
     * Attacker can forge or tamper with the cookie value.
     */
    public Object restoreSessionFromCookie(String cookieValue) {
        logger.info("Restoring session from cookie: " + cookieValue);
        // VULNERABILITY: No integrity check - cookie value is directly deserialized
        return deserializeFromBase64(cookieValue);
    }

    /**
     * VULNERABILITY: Deserializes booking data from an HTTP request body.
     * Intended to restore a "saved booking" but accepts arbitrary serialized objects.
     */
    public Object restoreBookingState(String serializedBooking) {
        logger.info("Restoring booking state from serialized data");
        // VULNERABILITY: No type checking, no class whitelist
        return deserializeFromBase64(serializedBooking);
    }
}

// Made with Bob
