package com.login.service;

import com.login.entity.User;
import com.login.repository.UserRepository;
import com.login.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    public Optional<Map<String, String>> authenticate(String username, String password, String role) {
        return userRepository.findByUsername(username)
                .filter(user -> user.getPassword().equals(password) && user.getRole().equals(role)) // ✅ Check username, password, and role
                .map(user -> {
                    String accessToken = jwtUtil.generateToken(user.getUsername(), user.getRole(), false);
                    String refreshToken = jwtUtil.generateToken(user.getUsername(), user.getRole(), true);

                    Map<String, String> response = new HashMap<>();
                    response.put("username", user.getUsername());
                    response.put("password", user.getPassword()); // ⚠️ Return plain-text password (only for testing)
                    response.put("role", user.getRole());
                    response.put("accessToken", accessToken);
                    response.put("refreshToken", refreshToken);
                    return response;
                });
    }

    // ✅ New Method: Refresh token generation
    public String refreshToken(String username, String role) {
        return jwtUtil.generateToken(username, role, true); // Generate new refresh token
    }
}
