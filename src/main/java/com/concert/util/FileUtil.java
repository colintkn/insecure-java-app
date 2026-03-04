package com.concert.util;

import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.logging.Logger;

/**
 * File utility class.
 *
 * VULNERABILITIES DEMONSTRATED:
 * 1. Open file permissions (world-readable/writable: 777)
 * 2. Path traversal - user-controlled file paths not sanitized
 * 3. Arbitrary file read from user-supplied path
 * 4. Arbitrary file write to user-supplied path
 * 5. Sensitive files (logs, configs) written with open permissions
 * 6. No file type validation on uploads
 * 7. Temp files created with insecure permissions
 */
@Component
public class FileUtil {

    private static final Logger logger = Logger.getLogger(FileUtil.class.getName());

    // VULNERABILITY: Base upload directory - path traversal can escape this
    private static final String UPLOAD_DIR = "/tmp/concert-uploads/";
    private static final String LOG_DIR    = "/tmp/concert-logs/";

    /**
     * VULNERABILITY: Path traversal - filename from user input is not sanitized.
     * An attacker can pass: ../../etc/passwd to read arbitrary files.
     */
    public String readFile(String filename) {
        // VULNERABILITY: No path sanitization - direct concatenation
        String filePath = UPLOAD_DIR + filename;
        logger.info("Reading file: " + filePath);

        try {
            // VULNERABILITY: Reads arbitrary file if path traversal succeeds
            return new String(Files.readAllBytes(Paths.get(filePath)));
        } catch (IOException e) {
            // VULNERABILITY: Error message reveals full file path
            throw new RuntimeException("Cannot read file at path: " + filePath + " - " + e.getMessage());
        }
    }

    // Code with java.lang.security.audit.overly-permissive-file-permission.overly-permissive-file-permission
// /**
//      * VULNERABILITY: Path traversal on write - attacker can overwrite arbitrary files.
//      * e.g., filename = "../../etc/cron.d/malicious" to write a cron job.
//      */
//     public void writeFile(String filename, String content) {
//         // VULNERABILITY: No path sanitization
//         String filePath = UPLOAD_DIR + filename;
//         logger.info("Writing file: " + filePath + " content length: " + content.length());
// 
//         try {
//             Path path = Paths.get(filePath);
//             Files.createDirectories(path.getParent());
//             Files.write(path, content.getBytes());
// 
//             // VULNERABILITY: Sets file permissions to 777 (world-readable and writable)
//             Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxrwxrwx");
//             Files.setPosixFilePermissions(path, perms);
// 
//             logger.info("File written with 777 permissions: " + filePath);
//         } catch (IOException e) {
//             throw new RuntimeException("File write failed: " + e.getMessage());
//         }
//     }

// Code fix for java.lang.security.audit.overly-permissive-file-permission.overly-permissive-file-permission 
/**
     * Fixes: Path traversal on write - attacker can no longer overwrite arbitrary files.
     * e.g., filename = "../../etc/cron.d/malicious" to write a cron job.
     */
    public void writeFile(String filename, String content) {
        // Sanitize the filename to prevent path traversal attacks
        String sanitizedFilename = sanitizeFilename(filename);
        String filePath = UPLOAD_DIR + sanitizedFilename;
        logger.info("Writing file: " + filePath + " content length: " + content.length());

        try {
            Path path = Paths.get(filePath);
            Files.createDirectories(path.getParent());
            Files.write(path, content.getBytes());

            // Set file permissions to a more restrictive value (644)
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-r--r--");
            Files.setPosixFilePermissions(path, perms);

            logger.info("File written with 644 permissions: " + filePath);
        } catch (IOException e) {
            throw new RuntimeException("File write failed: " + e.getMessage());
        }
    }

    /**
     * Sanitizes the filename to prevent path traversal attacks.
     * @param filename The original filename provided by the user.
     * @return A sanitized filename that is safe to use.
     */
    private String sanitizeFilename(String filename) {
        // Check for path traversal patterns and replace them with a safe value
        return filename.replaceAll("([^\\w\\s\\.\\-])", "_");
    }


    /**
     * VULNERABILITY: Saves uploaded file with no type validation.
     * Allows uploading .jsp, .php, .sh, .exe files - potential webshell upload.
     * Also uses the original filename from the client (path traversal risk).
     */
    public String saveUploadedFile(String originalFilename, byte[] fileContent) {
        // VULNERABILITY: Uses client-supplied filename directly (path traversal + arbitrary extension)
        String savePath = UPLOAD_DIR + originalFilename;
        logger.info("Saving uploaded file: " + savePath);

        try {
            Path path = Paths.get(savePath);
            Files.createDirectories(path.getParent());
            Files.write(path, fileContent);

            // VULNERABILITY: World-readable permissions on uploaded file
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxrwxrwx");
            Files.setPosixFilePermissions(path, perms);

            return savePath;
        } catch (IOException e) {
            throw new RuntimeException("Upload failed: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Creates a temp file with world-readable permissions.
     * Temp files may contain sensitive data (e.g., payment info, tokens).
     */
    public File createTempFile(String prefix, String content) {
        try {
            // VULNERABILITY: Temp file created in world-readable /tmp directory
            File tempFile = File.createTempFile(prefix, ".tmp");
            tempFile.setReadable(true, false);  // VULNERABILITY: readable by all users
            tempFile.setWritable(true, false);  // VULNERABILITY: writable by all users

            try (FileWriter fw = new FileWriter(tempFile)) {
                fw.write(content);
            }

            logger.info("Temp file created: " + tempFile.getAbsolutePath());
            return tempFile;
        } catch (IOException e) {
            throw new RuntimeException("Temp file creation failed: " + e.getMessage());
        }
    }

    // Code with java.lang.security.audit.overly-permissive-file-permission.overly-permissive-file-permission
// /**
//      * VULNERABILITY: Writes application logs (which contain sensitive data) with 777 permissions.
//      * Any local user on the system can read the log file.
//      */
//     public void writeLogFile(String logContent) {
//         String logPath = LOG_DIR + "concert-app.log";
//         try {
//             Path path = Paths.get(logPath);
//             Files.createDirectories(path.getParent());
//             // VULNERABILITY: Appends to log file with open permissions
//             Files.write(path, (logContent + "\n").getBytes(),
//                         StandardOpenOption.CREATE, StandardOpenOption.APPEND);
// 
//             // VULNERABILITY: Log file set to 777
//             Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxrwxrwx");
//             Files.setPosixFilePermissions(path, perms);
//         } catch (IOException e) {
//             logger.severe("Failed to write log: " + e.getMessage());
//         }
//     }

// Code fix for java.lang.security.audit.overly-permissive-file-permission.overly-permissive-file-permission 
/**
 * Fixes the vulnerability by setting appropriate file permissions for the log file.
 * Instead of granting 777 permissions, we set read and write permissions for the owner,
 * and no permissions for others. This adheres to the principle of least privilege.
 */
public void writeLogFile(String logContent) {
    String logPath = LOG_DIR + "concert-app.log";
    try {
        Path path = Paths.get(logPath);
        Files.createDirectories(path.getParent());
        // Write to log file with appropriate permissions
        Files.write(path, (logContent + "\n").getBytes(),
                    StandardOpenOptions.CREATE, StandardOpenOptions.APPEND);

        // Set file permissions: owner has read and write, others have no permissions
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
        Files.setPosixFilePermissions(path, perms);
    } catch (IOException e) {
        logger.severe("Failed to write log: " + e.getMessage());
    }
}


    /**
     * VULNERABILITY: Reads a config file from a user-supplied path.
     * Could expose /etc/passwd, application.properties, or other sensitive files.
     */
    public String readConfigFile(String configPath) {
        // VULNERABILITY: No restriction on which paths can be read
        logger.info("Reading config from: " + configPath);
        try {
            return new String(Files.readAllBytes(Paths.get(configPath)));
        } catch (IOException e) {
            // VULNERABILITY: Reveals whether the file exists and its path
            throw new RuntimeException("Config file not found: " + configPath);
        }
    }

    /**
     * VULNERABILITY: Deletes a file at a user-supplied path with no validation.
     * An attacker could delete critical system or application files.
     */
    public boolean deleteFile(String filename) {
        // VULNERABILITY: No path sanitization - can delete arbitrary files
        String filePath = UPLOAD_DIR + filename;
        logger.warning("Deleting file: " + filePath);
        try {
            return Files.deleteIfExists(Paths.get(filePath));
        } catch (IOException e) {
            throw new RuntimeException("Delete failed: " + e.getMessage());
        }
    }
}

// Made with Bob
