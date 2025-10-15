package com.vulnbank.api.controller;

import com.vulnbank.api.model.User;
import com.vulnbank.api.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private UserRepository userRepository;
    
    @PersistenceContext
    private EntityManager entityManager;
    
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        // VULNERABILITY: No input validation
        // VULNERABILITY: Password stored in plain text (we'll add this vulnerability intentionally)
        
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username already exists");
        }
        
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body("Email already exists");
        }
        
        // Save user with plain text password (VULNERABLE - we'll fix this later)
        User savedUser = userRepository.save(user);
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "User registered successfully");
        response.put("userId", savedUser.getId());
        response.put("username", savedUser.getUsername());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * VULNERABILITY: SQL Injection (OWASP A03:2021 - Injection)
     * 
     * This endpoint is critically vulnerable to SQL injection attacks because
     * it uses string concatenation to build SQL queries with user input.
     * 
     * EXPLOIT EXAMPLES:
     * 1. Bypass authentication:
     *    username: admin' OR '1'='1
     *    password: anything
     * 
     * 2. Comment out password check:
     *    username: admin'--
     *    password: (not checked)
     * 
     * 3. Union-based injection:
     *    username: ' UNION SELECT * FROM users--
     *    password: anything
     * 
     * WHY THIS IS DANGEROUS:
     * - Attacker can bypass authentication completely
     * - Can access any account without knowing password
     * - Can extract entire database contents
     * - Can modify or delete data
     * - Can execute arbitrary SQL commands
     * 
     * SECURE FIX: Use parameterized queries or JPA methods (see secure branch)
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");
        
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        // Building SQL query with string concatenation
        String sql = "SELECT * FROM users WHERE username = '" + username + 
                     "' AND password = '" + password + "'";
        
        // Log the query (in real attacks, this wouldn't be visible)
        System.out.println("Executing SQL: " + sql);
        
        try {
            Query query = entityManager.createNativeQuery(sql, User.class);
            List<User> results = query.getResultList();
            
            if (results.isEmpty()) {
                return ResponseEntity.status(401).body("Invalid credentials");
            }
            
            User user = results.get(0);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Login successful");
            response.put("userId", user.getId());
            response.put("username", user.getUsername());
            response.put("balance", user.getBalance());
            
            // ADDITIONAL VULNERABILITY: No JWT token, no session management
            // In secure version, we would return a JWT token here
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            // VULNERABILITY: Exposing database errors to user
            return ResponseEntity.status(500)
                .body("Database error: " + e.getMessage());
        }
    }
}