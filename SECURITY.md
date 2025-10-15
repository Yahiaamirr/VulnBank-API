# Security Analysis - VulnBank API

⚠️ **DISCLAIMER:** This application contains intentional security vulnerabilities for educational purposes only.

## Overview
This document provides detailed technical analysis of each vulnerability implemented in VulnBank API, including:
- OWASP classification
- Vulnerable code locations
- Exploitation steps
- Impact assessment
- Remediation guidance

---

## Implemented Vulnerabilities

### VULN-001: Cryptographic Failures - Plain Text Password Storage

**OWASP Category:** A02:2021 – Cryptographic Failures  
**Severity:** 🔴 Critical  
**CWE ID:** CWE-256 (Plaintext Storage of a Password)  
**Status:** ✅ Implemented

#### Description
User passwords are stored in the database without any hashing or encryption, violating fundamental security principles.

#### Vulnerable Code
**File:** `src/main/java/com/vulnbank/api/controller/AuthController.java`  
**Method:** `register()`
```java
// VULNERABILITY: Password stored in plain text
User savedUser = userRepository.save(user);
```

#### Proof of Concept
1. Register a new user via POST `/api/auth/register`:
```json
{
    "username": "victim",
    "email": "victim@example.com",
    "password": "MySecretPassword123"
}
```

2. Access H2 Console at `http://localhost:8080/h2-console`
3. Execute query: `SELECT * FROM USERS;`
4. Observe password stored as `MySecretPassword123` in plain text

**Evidence:**  
![Database showing plain text password](screenshots/02-plaintext-password-database.png)

*Screenshot shows user 'testuser' with password 'password123' stored in plain text in the USERS table.*

#### Impact
- **Confidentiality Breach:** Database compromise exposes all user passwords
- **Account Takeover:** Attackers gain immediate access to all accounts
- **Credential Reuse:** Users often reuse passwords across services
- **Compliance Violation:** Violates GDPR, PCI-DSS, HIPAA requirements
- **Reputational Damage:** Severe trust and brand damage

#### Attack Scenario
```
1. Attacker gains database access (SQL injection, backup theft, insider threat)
2. Attacker exports USERS table
3. Attacker logs in as any user with their plain text password
4. Attacker accesses sensitive financial data and transfers funds
```

#### Remediation
**Secure Implementation:**
```java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Autowired
private BCryptPasswordEncoder passwordEncoder;

@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody User user) {
    // Hash password before storing
    String hashedPassword = passwordEncoder.encode(user.getPassword());
    user.setPassword(hashedPassword);
    
    User savedUser = userRepository.save(user);
    // ... rest of code
}
```

**Configuration Required:**
```java
@Bean
public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

#### References
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
- [Spring Security Password Encoding](https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html)

---

### VULN-002: Software and Data Integrity Failures - Mass Assignment

**OWASP Category:** A08:2021 – Software and Data Integrity Failures  
**Severity:** 🟠 High  
**CWE ID:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)  
**Status:** ✅ Implemented

#### Description
The registration endpoint accepts raw User objects without validation, allowing attackers to set arbitrary fields including their account balance.

#### Vulnerable Code
**File:** `src/main/java/com/vulnbank/api/controller/AuthController.java`  
**Method:** `register()`
```java
@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody User user) {
    // VULNERABILITY: Accepts all User fields without validation
    // Attacker can set balance, id, or any other field
```

#### Proof of Concept
**Normal Registration:**
```json
POST /api/auth/register
{
    "username": "normaluser",
    "email": "normal@example.com",
    "password": "password123"
}
// Result: balance = 0.0
```

**Malicious Registration:**
```json
POST /api/auth/register
{
    "username": "hacker",
    "email": "hacker@example.com",
    "password": "password123",
    "balance": 9999999.99
}
// Result: balance = 9999999.99 (attacker sets own balance!)
```

#### Impact
- **Financial Loss:** Users create accounts with arbitrary balances
- **Business Logic Bypass:** Circumvents all balance validation
- **Data Integrity:** Attackers modify protected fields
- **Privilege Escalation:** Could set admin flags if they existed

#### Remediation
**Use Data Transfer Objects (DTOs):**
```java
// Create RegisterRequest DTO
public class RegisterRequest {
    private String username;
    private String email;
    private String password;
    // No balance field - user cannot set it
}

@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
    User user = new User();
    user.setUsername(request.getUsername());
    user.setEmail(request.getEmail());
    user.setPassword(passwordEncoder.encode(request.getPassword()));
    user.setBalance(0.0); // Set by server, not client
    
    User savedUser = userRepository.save(user);
}
```

#### References
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-915](https://cwe.mitre.org/data/definitions/915.html)

---

### VULN-003: Injection - SQL Injection in Login

**OWASP Category:** A03:2021 – Injection  
**Severity:** 🔴 Critical  
**CWE ID:** CWE-89 (SQL Injection)  
**Status:** ✅ Implemented

#### Description
The login endpoint constructs SQL queries using string concatenation with unsanitized user input, allowing attackers to inject malicious SQL code and bypass authentication.

#### Vulnerable Code
**File:** `src/main/java/com/vulnbank/api/controller/AuthController.java`  
**Method:** `login()`
```java
// VULNERABLE: String concatenation in SQL query
String sql = "SELECT * FROM users WHERE username = '" + username + 
             "' AND password = '" + password + "'";
Query query = entityManager.createNativeQuery(sql, User.class);
```

#### Proof of Concept

**Attack 1: Authentication Bypass**
```json
POST /api/auth/login
{
    "username": "admin' OR '1'='1",
    "password": "anything"
}
```

**Resulting SQL:**
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'anything'
```

**Result:** Login succeeds without valid password because `'1'='1'` is always true.

**Attack 2: Comment-Based Bypass**
```json
POST /api/auth/login
{
    "username": "admin'--",
    "password": "ignored"
}
```

**Resulting SQL:**
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = 'ignored'
```

**Result:** Everything after `--` is commented out, password check is bypassed.

**Evidence:**  
![SQL Injection Bypass](screenshots/04-sql-injection-bypass.png)  
![SQL Injection Console](screenshots/05-sql-injection-console.png)

#### Impact
- **Critical Authentication Bypass:** Access any account without password
- **Data Exfiltration:** Attackers can extract entire database
- **Data Manipulation:** Can update or delete records
- **Privilege Escalation:** Access admin accounts
- **Complete System Compromise:** Possible remote code execution in some databases

#### Attack Scenario
```
1. Attacker discovers login endpoint
2. Attempts SQL injection: username = "admin' OR '1'='1"
3. Successfully logs in as admin without password
4. Accesses all user accounts and financial data
5. Transfers funds, steals sensitive information
6. Deletes audit logs to cover tracks
```

#### Remediation

**Secure Implementation - Use JPA Repository:**
```java
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    // Use parameterized query through JPA
    Optional<User> userOpt = userRepository.findByUsername(request.getUsername());
    
    if (userOpt.isEmpty()) {
        return ResponseEntity.status(401).body("Invalid credentials");
    }
    
    User user = userOpt.get();
    
    // Verify password with BCrypt
    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
        return ResponseEntity.status(401).body("Invalid credentials");
    }
    
    // Generate JWT token
    String token = jwtService.generateToken(user);
    
    return ResponseEntity.ok(new LoginResponse(token, user.getUsername()));
}
```

**Key Security Improvements:**
1. Uses JPA repository methods (parameterized queries)
2. Password verified with BCrypt
3. Returns JWT token instead of sensitive user data
4. Generic error messages (don't reveal if username exists)
5. No raw SQL construction

#### References
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)

## Vulnerabilities To Be Implemented


### 🔜 VULN-004: Broken Access Control
**OWASP:** A01:2021  
**Severity:** 🔴 Critical  
**Status:** ⏳ Pending

### 🔜 VULN-005: Identification and Authentication Failures
**OWASP:** A07:2021  
**Severity:** 🟠 High  
**Status:** ⏳ Pending

### 🔜 VULN-006: Security Misconfiguration
**OWASP:** A05:2021  
**Severity:** 🟠 High  
**Status:** ⏳ Pending

---

## Testing Guide

### Prerequisites
- Postman or curl installed
- Application running on `http://localhost:8080`
- H2 Console accessible at `http://localhost:8080/h2-console`

### Test Each Vulnerability
Each vulnerability section above includes:
1. Exploitation steps
2. Expected results
3. Evidence location (screenshots)

---

## Secure Branch
All vulnerabilities will be fixed in the `secure` branch with:
- Secure implementations
- Code comparisons (before/after)
- Security best practices
- Additional protective measures

---

**Last Updated:** October 15, 2025  
**Author:** Yahia Amir Anwar