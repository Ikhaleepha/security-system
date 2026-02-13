package com.mam.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mam.model.AuthRequest;
import com.mam.model.JwtUserDetails;
import com.mam.service.JwtTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Autowired
    private ObjectMapper objectMapper;

    private String generateTestToken(Long userId, String username, String... roles) {
        List<SimpleGrantedAuthority> authorities = java.util.Arrays.stream(roles)
                .map(SimpleGrantedAuthority::new)
                .toList();
        JwtUserDetails userDetails = new JwtUserDetails(userId, username, "", authorities, true);
        return jwtTokenService.generateToken(userDetails);
    }

    // ===== PUBLIC ENDPOINT TESTS =====

    @Test
    void healthEndpoint_shouldBePubliclyAccessible() throws Exception {
        mockMvc.perform(get("/api/public/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    // ===== AUTHENTICATION TESTS =====

    @Test
    void login_withValidCredentials_shouldReturnToken() throws Exception {
        AuthRequest request = new AuthRequest("user", "password");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.username").value("user"));
    }

    @Test
    void login_withInvalidCredentials_shouldReturn401() throws Exception {
        AuthRequest request = new AuthRequest("user", "wrongpassword");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_withNonExistentUser_shouldReturn401() throws Exception {
        AuthRequest request = new AuthRequest("nonexistent", "password");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    // ===== USER ENDPOINT TESTS =====

    @Test
    void userMe_withoutToken_shouldReturn401() throws Exception {
        mockMvc.perform(get("/api/user/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    void userMe_withValidToken_shouldReturnUserInfo() throws Exception {
        String token = generateTestToken(1L, "testuser", "ROLE_USER");

        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.userId").value(1));
    }

    // ===== ADMIN ENDPOINT TESTS =====

    @Test
    void adminUsers_withoutToken_shouldReturn401() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminUsers_withUserRole_shouldReturn403() throws Exception {
        String token = generateTestToken(1L, "user", "ROLE_USER");

        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Forbidden"));
    }

    @Test
    void adminUsers_withAdminRole_shouldReturnUsers() throws Exception {
        String token = generateTestToken(2L, "admin", "ROLE_USER", "ROLE_ADMIN");

        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    // ===== JWT VALIDATION TESTS =====

    @Test
    void request_withMalformedToken_shouldReturn401() throws Exception {
        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer invalid.token.here"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void request_withMissingBearerPrefix_shouldReturn401() throws Exception {
        String token = generateTestToken(1L, "user", "ROLE_USER");

        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", token))
                .andExpect(status().isUnauthorized());
    }
}
