package com.concert.util;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * Cryptography utility class.
 *
 * VULNERABILITIES DEMONSTRATED:
 * 1. Use of broken/weak hash algorithms (MD5, SHA-1)
 * 2. Use of weak encryption algorithm (DES)
 * 3. ECB mode encryption (no IV, deterministic output)
 * 4. Hardcoded encryption key in source code
 * 5. Insufficient key size (56-bit DES)
 * 6. Custom "encryption" that is just Base64 encoding (not encryption)
 * 7. Hardcoded static salt for password hashing
 */
@Component
public class CryptoUtil {

    private static final Logger logger = Logger.getLogger(CryptoUtil.class.getName());

    // VULNERABILITY: Hardcoded encryption key in source code
    private static final String HARDCODED_AES_KEY = "MySecretKey12345"; // 16 bytes
    private static final String HARDCODED_DES_KEY = "DESKey12";         // 8 bytes for DES

    // VULNERABILITY: Hardcoded static salt (should be random per-user)
    private static final String STATIC_SALT = "concert_salt_2024";

    /**
     * VULNERABILITY: Uses MD5 for password hashing.
     * MD5 is cryptographically broken and unsuitable for password storage.
     * Should use bcrypt, scrypt, or Argon2 instead.
     */
    public String hashPasswordMD5(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            // VULNERABILITY: Static salt concatenated (not random per-user)
            byte[] hash = md.digest((STATIC_SALT + password).getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            logger.info("MD5 hash generated for password: " + password); // VULNERABILITY: logs plaintext password
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 not available", e);
        }
    }

    /**
     * VULNERABILITY: Uses SHA-1 for password hashing.
     * SHA-1 is deprecated for security use and vulnerable to collision attacks.
     */
    public String hashPasswordSHA1(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hash = md.digest(password.getBytes()); // VULNERABILITY: No salt at all
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 not available", e);
        }
    }

    /**
     * VULNERABILITY: Uses DES encryption (56-bit key, broken since 1999).
     * DES is trivially brute-forceable with modern hardware.
     * Also uses ECB mode which is deterministic and leaks patterns.
     */
    public String encryptWithDES(String plaintext) {
        try {
            // VULNERABILITY: DES with hardcoded key
            SecretKeySpec keySpec = new SecretKeySpec(HARDCODED_DES_KEY.getBytes(), "DES");
            // VULNERABILITY: ECB mode - no IV, same plaintext always produces same ciphertext
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            logger.severe("DES encryption failed: " + e.getMessage());
            throw new RuntimeException("Encryption error", e);
        }
    }

    /**
     * VULNERABILITY: AES used in ECB mode (no IV).
     * ECB mode is insecure - identical plaintext blocks produce identical ciphertext blocks.
     * Should use AES/GCM/NoPadding or AES/CBC with random IV.
     */
    public String encryptWithAES_ECB(String plaintext) {
        try {
            // VULNERABILITY: Hardcoded key
            SecretKeySpec keySpec = new SecretKeySpec(HARDCODED_AES_KEY.getBytes(), "AES");
            // VULNERABILITY: ECB mode
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("AES ECB encryption error", e);
        }
    }

    /**
     * VULNERABILITY: "Encryption" that is just Base64 encoding.
     * Base64 is encoding, NOT encryption. Anyone can decode it trivially.
     * This gives a false sense of security.
     */
    public String encryptSensitiveData(String data) {
        // VULNERABILITY: This is NOT encryption - it's just Base64 encoding
        logger.info("'Encrypting' sensitive data: " + data); // VULNERABILITY: logs plaintext
        return Base64.getEncoder().encodeToString(data.getBytes());
    }

    /**
     * VULNERABILITY: Decryption using the same hardcoded key.
     * Key management is non-existent.
     */
    public String decryptWithAES_ECB(String ciphertext) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(HARDCODED_AES_KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            String result = new String(decrypted);
            logger.info("Decrypted value: " + result); // VULNERABILITY: logs decrypted sensitive data
            return result;
        } catch (Exception e) {
            throw new RuntimeException("AES ECB decryption error", e);
        }
    }

    /**
     * VULNERABILITY: Generates a weak random token using Math.random() instead of
     * SecureRandom. Math.random() is not cryptographically secure.
     */
    public String generateSessionToken(String username) {
        // VULNERABILITY: Math.random() is not cryptographically secure
        long weakRandom = (long) (Math.random() * 1_000_000);
        // VULNERABILITY: Predictable token structure
        return username + "_" + weakRandom;
    }

    /**
     * VULNERABILITY: Weak key generation using a fixed seed.
     * Produces the same key every time if seed is known.
     */
    public SecretKey generateWeakKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            // VULNERABILITY: Fixed key size of 128 bits is acceptable, but no secure random seed
            keyGen.init(128);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Key generation failed", e);
        }
    }

    /**
     * VULNERABILITY: Compares hashes using String.equals() which is vulnerable to
     * timing attacks. Should use MessageDigest.isEqual() for constant-time comparison.
     */
    public boolean verifyPassword(String inputPassword, String storedHash) {
        String inputHash = hashPasswordMD5(inputPassword);
        // VULNERABILITY: Non-constant-time comparison (timing attack possible)
        return inputHash.equals(storedHash);
    }
}

// Made with Bob
