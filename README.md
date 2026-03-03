# Concert Booking System — Intentionally Vulnerable Java Application

> ⚠️ **WARNING: This application is intentionally insecure.**
> It is designed **solely for educational and security training purposes**.
> **DO NOT deploy this application in any production or internet-facing environment.**

---

## Overview

This is a Spring Boot-based concert ticket booking system that intentionally demonstrates **8 categories of common security vulnerabilities** found in real-world Java applications. Each vulnerability is clearly annotated in the source code with `// VULNERABILITY:` comments.

---

## Project Structure

```
concert-booking/
├── pom.xml
└── src/main/
    ├── java/com/concert/
    │   ├── ConcertBookingApplication.java       # App entry point
    │   ├── config/
    │   │   ├── SecurityConfig.java              # Weak Spring Security config
    │   │   └── DataInitializer.java             # Seeds weak default accounts
    │   ├── controller/
    │   │   ├── UserController.java              # Debug endpoints, no input validation
    │   │   └── BookingController.java           # IDOR, file upload, path traversal
    │   ├── model/
    │   │   ├── User.java                        # Weak auth logic, plain-text passwords
    │   │   └── Booking.java                     # Sensitive data in plain text
    │   ├── repository/
    │   │   └── UserRepository.java              # JPA repository
    │   └── util/
    │       ├── CryptoUtil.java                  # Insecure cryptography (MD5, DES, ECB)
    │       ├── DatabaseUtil.java                # Hardcoded credentials, SQL injection
    │       ├── DeserializationUtil.java         # Unsafe Java deserialization
    │       ├── FileUtil.java                    # Open permissions, path traversal
    │       └── LoggingUtil.java                 # Logs sensitive data (passwords, CVV)
    └── resources/
        └── application.properties               # Hardcoded API keys and secrets
```

---

## Vulnerability Categories

### 1. 🔑 Hardcoded Passwords or API Keys in Code

| Location | Description |
|---|---|
| `application.properties` | Stripe API keys (`sk_live_...`), SendGrid key, AWS access/secret keys hardcoded |
| `DatabaseUtil.java` | MySQL root password `P@ssw0rd!MySQL#2024` hardcoded as `static final` |
| `UserController.java` | Admin credentials `admin / admin123` and `ADMIN_SECRET_KEY` hardcoded |
| `SecurityConfig.java` | No secret management — all secrets from hardcoded properties |
| `DataInitializer.java` | Default accounts seeded with hardcoded weak passwords |
| `application.properties` | JWT secret `mysupersecretkey123`, admin credentials hardcoded |

**Risk:** Any developer with source code access (or anyone who decompiles the JAR) can extract all credentials. Secrets committed to version control are permanently exposed.

---

### 2. 🐛 Debug Endpoints Left Enabled

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/debug/env` | GET | Dumps **all environment variables** including AWS keys, DB passwords |
| `GET /api/debug/system` | GET | Dumps all JVM system properties (classpath, OS, file paths) |
| `GET /api/debug/config` | GET | Returns live values of JWT secret, payment API key, DB password |
| `POST /api/debug/sql` | POST | Executes **arbitrary SQL** on the production database |
| `POST /api/debug/deserialize` | POST | Deserializes arbitrary user-supplied Base64 data (RCE risk) |
| `GET /api/debug/file` | GET | Reads **any file** on the server by path |
| `GET /api/debug/session` | GET | Deserializes session cookie without validation |
| `GET /h2-console` | GET | H2 database console open to all, including remote hosts |

**Risk:** Debug endpoints expose the entire application internals. The `/debug/sql` endpoint alone allows full database compromise. The `/debug/deserialize` endpoint enables Remote Code Execution.

---

### 3. 🔐 Insecure Use of Cryptography

| Location | Description |
|---|---|
| `CryptoUtil.hashPasswordMD5()` | Uses **MD5** for password hashing — broken since 2004 |
| `CryptoUtil.hashPasswordSHA1()` | Uses **SHA-1** — deprecated, collision attacks known |
| `CryptoUtil.encryptWithDES()` | Uses **DES** (56-bit key) — brute-forceable in hours |
| `CryptoUtil.encryptWithAES_ECB()` | AES in **ECB mode** — deterministic, leaks data patterns |
| `CryptoUtil.encryptSensitiveData()` | Uses **Base64 encoding** and calls it "encryption" |
| `CryptoUtil.generateSessionToken()` | Uses `Math.random()` — **not cryptographically secure** |
| `CryptoUtil.verifyPassword()` | Uses `String.equals()` — vulnerable to **timing attacks** |
| `CryptoUtil.java` | **Hardcoded encryption keys** as `static final` strings |
| `SecurityConfig.java` | `NoOpPasswordEncoder` — stores passwords in **plain text** |

**Risk:** Passwords can be cracked instantly with rainbow tables. Encrypted data can be decrypted by anyone with the hardcoded key. Session tokens are predictable and forgeable.

---

### 4. ✏️ Missing Input Validation

| Location | Description |
|---|---|
| `UserController.register()` | No validation on username, email, password (accepts `password="1"`) |
| `UserController.login()` | No null/empty check on credentials |
| `UserController.updateUser()` | Mass assignment — attacker can set `role=ADMIN` |
| `UserController.resetPassword()` | No token required, no password strength check |
| `BookingController.createBooking()` | `quantity` can be negative, `totalPrice` can be 0 |
| `BookingController.getBooking()` | `bookingId` not validated — SQL Injection |
| `BookingController.uploadTicket()` | No file type or size validation — webshell upload possible |
| `BookingController.downloadFile()` | `filename` not sanitized — path traversal |
| `DatabaseUtil.findUserByUsername()` | Raw SQL string concatenation — SQL Injection |
| `DatabaseUtil.validateLogin()` | SQL Injection — `' OR 1=1 --` bypasses authentication |
| `DatabaseUtil.searchConcerts()` | SQL Injection in search — `%'; DROP TABLE concerts; --` |

**Risk:** SQL Injection can lead to full database compromise. Missing validation allows XSS payloads, negative pricing, privilege escalation, and arbitrary file access.

---

### 5. 📋 Logging Sensitive Data

| Location | Description |
|---|---|
| `LoggingUtil.logLoginAttempt()` | Logs **plaintext password** on every login attempt |
| `LoggingUtil.logUserRegistration()` | Logs full `User.toString()` including password and credit card |
| `LoggingUtil.logPaymentProcessing()` | Logs **full card number and CVV** — PCI-DSS violation |
| `LoggingUtil.logSessionCreated()` | Logs **full JWT token** — replayable by log reader |
| `LoggingUtil.logApiRequest()` | Logs **API keys** in plaintext |
| `LoggingUtil.logHttpRequest()` | Logs **Authorization header** (Bearer tokens, Basic auth) |
| `LoggingUtil.logPasswordReset()` | Logs **password reset tokens** — account takeover risk |
| `LoggingUtil.logApplicationStartup()` | Logs **all secrets** (JWT, DB password, API key) at startup |
| `CryptoUtil.hashPasswordMD5()` | Logs the **plaintext password** being hashed |
| `DatabaseUtil.validateLogin()` | Logs the full SQL query including **embedded credentials** |
| `DatabaseUtil.savePaymentDetails()` | Logs card number, CVV, expiry before DB insert |
| `application.properties` | `logging.level.root=DEBUG` — verbose logging enabled globally |

**Risk:** Log files become a treasure trove for attackers. Anyone with log access (sysadmin, log aggregation service, SIEM) can harvest credentials, tokens, and payment data.

---

### 6. 🔓 Weak Authentication Logic

| Location | Description |
|---|---|
| `User.authenticate()` | **Backdoor token** `superadmin_backdoor_2024` bypasses all auth |
| `User.authenticate()` | **Plain text password comparison** — no hashing |
| `User.authenticate()` | **No account lockout** after failed attempts |
| `User.isPasswordValid()` | Only requires **length >= 4** — accepts `"1234"` |
| `User.generatePasswordResetToken()` | **Predictable token** based on username + Unix timestamp |
| `UserController.resetPassword()` | Password reset requires **only username** — no token/OTP |
| `UserController.adminGetAllUsers()` | Admin check via **hardcoded header value** instead of RBAC |
| `DataInitializer.java` | Default accounts: `admin/admin123`, `testuser/1234`, `guest/""` |
| `SecurityConfig.java` | `antMatchers("/**").permitAll()` — **all endpoints public** |
| `SecurityConfig.java` | Session fixation protection **disabled** |
| `UserController.login()` | Returns **full user object** (including password) on success |

**Risk:** Any attacker can use the backdoor token to authenticate as any user. Weak passwords are trivially guessable. No lockout means unlimited brute-force attempts.

---

### 7. 🌐 Open Permissions

| Location | Description |
|---|---|
| `SecurityConfig.java` | `antMatchers("/**").permitAll()` — every endpoint is public |
| `SecurityConfig.java` | CSRF disabled globally |
| `SecurityConfig.java` | CORS allows **all origins** (`*`) with credentials |
| `SecurityConfig.java` | `X-Frame-Options` disabled — clickjacking possible |
| `SecurityConfig.java` | No HTTPS enforcement |
| `FileUtil.writeFile()` | Files written with **777 permissions** (world read/write/execute) |
| `FileUtil.saveUploadedFile()` | Uploaded files saved with **777 permissions** |
| `FileUtil.createTempFile()` | Temp files set `readable(true, false)` — world-readable |
| `FileUtil.writeLogFile()` | Log files set to **777** — any local user can read logs |
| `application.properties` | `spring.h2.console.settings.web-allow-others=true` — H2 open to network |
| `UserController.java` | No ownership checks — any user can read/modify any other user |
| `BookingController.java` | No ownership checks — any user can cancel any booking (IDOR) |

**Risk:** Any unauthenticated user can access all API endpoints. Files with 777 permissions allow any local OS user to read sensitive data. CORS misconfiguration enables cross-site request forgery from any website.

---

### 8. 💣 Unsafe Deserialization

| Location | Description |
|---|---|
| `DeserializationUtil.deserializeObject()` | Raw `ObjectInputStream` with **no class filtering** |
| `DeserializationUtil.deserializeFromBase64()` | Deserializes **user-supplied Base64** data directly |
| `DeserializationUtil.deserializeFromFile()` | Deserializes from **user-controlled file path** |
| `DeserializationUtil.restoreSessionFromCookie()` | Deserializes **cookie value** without HMAC verification |
| `DeserializationUtil.restoreBookingState()` | Deserializes booking state from **HTTP request body** |
| `UserController.login()` | Serializes `User` object into a **cookie** (attack surface) |
| `BookingController.restoreBooking()` | Deserializes booking state from **POST body** |
| `UserController.debugDeserialize()` | Debug endpoint that deserializes **arbitrary data** |
| `User.java`, `Booking.java` | Both implement `Serializable` without `readObject()` validation |

**Risk:** Using tools like [ysoserial](https://github.com/frohoff/ysoserial), an attacker can craft a malicious serialized payload that, when deserialized, executes arbitrary OS commands (Remote Code Execution). This is one of the most critical Java vulnerabilities (CVE-2015-4852, CVE-2016-4437, etc.).

---

## How to Build and Run

```bash
# Build the project
mvn clean package -DskipTests

# Run the application
mvn spring-boot:run
```

The application starts on `http://localhost:8080`.

---

## Default Accounts (Seeded on Startup)

| Username  | Password  | Role  |
|-----------|-----------|-------|
| admin     | admin123  | ADMIN |
| testuser  | 1234      | USER  |
| guest     | (empty)   | USER  |

---

## Example Attack Scenarios

### SQL Injection Login Bypass
```
POST /api/login
{"username": "' OR 1=1 --", "password": "anything"}
```

### Privilege Escalation via Mass Assignment
```
PUT /api/users/1
{"username": "testuser", "role": "ADMIN", "password": "newpass"}
```

### Path Traversal — Read /etc/passwd
```
GET /api/bookings/download?filename=../../etc/passwd
GET /api/debug/file?path=/etc/passwd
```

### Dump All Secrets via Debug Endpoint
```
GET /api/debug/config
GET /api/debug/env
```

### Execute Arbitrary SQL
```
POST /api/debug/sql
{"sql": "DROP TABLE users"}
```

### Unsafe Deserialization (RCE with ysoserial)
```bash
java -jar ysoserial.jar CommonsCollections1 "calc.exe" | base64
POST /api/debug/deserialize
{"data": "<base64_payload>"}
```

### Password Reset Without Token
```
POST /api/reset-password
{"username": "admin", "newPassword": "hacked"}
```

---

## Security Fix References

| Vulnerability | Recommended Fix |
|---|---|
| Hardcoded secrets | Use environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager) |
| Debug endpoints | Remove or gate behind feature flags; never deploy to production |
| Weak crypto | Use BCrypt/Argon2 for passwords; AES-GCM with random IV for encryption |
| Missing validation | Use Bean Validation (`@NotNull`, `@Size`, `@Email`); validate all inputs |
| Sensitive logging | Use log masking; never log passwords, tokens, or card data |
| Weak auth | Implement account lockout, MFA, proper RBAC, secure password reset flow |
| Open permissions | Apply least-privilege; use `600`/`640` for sensitive files; enforce authentication |
| Unsafe deserialization | Use `ObjectInputFilter`; prefer JSON over Java serialization; validate before deserializing |

---

## License

This project is for **educational use only**. Do not use in production.