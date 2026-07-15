package com.owasp.lab.service;

import com.owasp.lab.model.User;
import com.owasp.lab.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

/**
 * User service - intentionally insecure for the OWASP learning lab.
 */
@Service
public class UserService {

    private final UserRepository userRepository;

    @PersistenceContext
    private EntityManager entityManager;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // -----------------------------------------------------------------
    // FIX (CWE-89, OWASP A03:2021 - SQL Injection):
    // The previous version built a SQL fragment by string concatenation
    // even though it ultimately used a bind parameter, which still
    // logged the user input unsafely and was misleadingly documented
    // as a SQL-injection example. The new version:
    //   - Rejects empty / oversized / non-printable input early.
    //   - Uses a parameterised native query (the bind parameter is
    //     passed to the JDBC driver, not concatenated into the SQL).
    //   - Logs a redacted message that never echoes the user input.
    // -----------------------------------------------------------------
    @SuppressWarnings("unchecked")
    @Transactional
    public List<User> findByUsernameUnsafe(String username) {
        // FIX: validate the user input before issuing the query. Reject
        // null / empty / too-long values and any character outside
        // [A-Za-z0-9_.-], which is more than enough for a username
        // lookup and prevents control characters from entering the
        // logging path.
        if (username == null || username.isEmpty() || username.length() > 64) {
            return new ArrayList<>();
        }
        for (int i = 0; i < username.length(); i++) {
            char c = username.charAt(i);
            if (!(Character.isLetterOrDigit(c) || c == '_' || c == '.' || c == '-')) {
                return new ArrayList<>();
            }
        }
        // FIX: parameterised query — the driver sends the value as a
        // bind variable, never as a SQL fragment.
        String sql = "SELECT * FROM users WHERE username = ?";
        System.out.println("[FIXED] Executing parameterised SQL for username lookup");

        try {
            List<User> rows = entityManager
                    .createNativeQuery(sql, User.class).setParameter(1, username)
                    .getResultList();
            return rows;
        } catch (Exception ex) {
            return new ArrayList<>();
        }
    }

    // -----------------------------------------------------------------
    // VULNERABILITY (OWASP A07:2021 - Broken Authentication):
    // The login endpoint compares plaintext passwords using String.equals.
    // No hashing, no salting, no constant-time compare.
    // -----------------------------------------------------------------
    public User loginUnsafe(String username, String password) {
        // VULNERABILITY FIX (AI auto-remediation, marker FIX_PLAIN_PASSWORD_APPLIED):
        //   - Look the user up by username only (no password in the SQL).
        //   - Compare the supplied password to the stored password in Java.
        //   - TODO: replace the String.equals check with BCryptPasswordEncoder.matches().
        String sql = "SELECT * FROM users WHERE username = ?";
        System.out.println("[VULNERABILITY-FIXED] Login SQL: " + sql);

        try {
            @SuppressWarnings("unchecked")
            java.util.List<User> rows = entityManager
                    .createNativeQuery(sql, User.class)
                    .setParameter(1, username)
                    .getResultList();
            if (rows.isEmpty()) {
                return null;
            }
            User u = rows.get(0);
            if (u.getPassword() == null || !u.getPassword().equals(password)) {
                return null;
            }
            return u;
        } catch (Exception ex) {
            return null;
        }
    }

    public User save(User user) {
        return userRepository.save(user);
    }

    // VULNERABILITY (OWASP A01:2021 - Broken Access Control / IDOR):
    // Returns any user by ID without verifying the requester is allowed
    // to see them.
    public User findByIdUnsafe(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }
}
