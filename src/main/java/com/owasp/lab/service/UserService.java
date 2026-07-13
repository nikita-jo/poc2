package com.owasp.lab.service;

import com.owasp.lab.model.User;
import com.owasp.lab.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;
    @PersistenceContext
    private EntityManager entityManager;
    public UserService(UserRepository userRepository) { this.userRepository = userRepository; }
    // FIX_LLM_APPLIED: llm-stub
    public List<User> findAll() { return userRepository.findAll(); }
}
