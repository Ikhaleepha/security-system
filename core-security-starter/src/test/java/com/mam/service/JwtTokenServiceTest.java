package com.mam.service;

import com.mam.config.JwtProperties;
import com.mam.exception.JwtAuthenticationException;
import com.mam.model.JwtUserDetails;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenServiceTest {

    private JwtTokenService jwtTokenService;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties();
        // 256-bit key for HS256
        properties.setSecret("dGhpcy1pcy1hLXZlcnktc2VjdXJlLWtleS1mb3ItdGVzdGluZy1wdXJwb3Nlcy1vbmx5LTEyMzQ1Njc4OTA=");
        properties.setExpirationMs(86400000L);
        properties.setIssuer("test-issuer");
        jwtTokenService = new JwtTokenService(properties);
    }

    @Test
    void generateToken_shouldContainExpectedClaims() {
        JwtUserDetails userDetails = new JwtUserDetails(
                1L, "testuser", "",
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                true
        );

        String token = jwtTokenService.generateToken(userDetails);
        Claims claims = jwtTokenService.validateAndExtractClaims(token);

        assertThat(claims.getSubject()).isEqualTo("testuser");
        assertThat(jwtTokenService.extractUserId(claims)).isEqualTo(1L);
        assertThat(jwtTokenService.extractRoles(claims)).contains("ROLE_USER");
        assertThat(claims.getIssuer()).isEqualTo("test-issuer");
    }

    @Test
    void generateToken_withMultipleRoles_shouldContainAllRoles() {
        JwtUserDetails userDetails = new JwtUserDetails(
                2L, "admin", "",
                List.of(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")
                ),
                true
        );

        String token = jwtTokenService.generateToken(userDetails);
        Claims claims = jwtTokenService.validateAndExtractClaims(token);

        assertThat(jwtTokenService.extractRoles(claims))
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void validateToken_withValidToken_shouldReturnClaims() {
        JwtUserDetails userDetails = new JwtUserDetails(
                1L, "testuser", "",
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                true
        );

        String token = jwtTokenService.generateToken(userDetails);
        Claims claims = jwtTokenService.validateAndExtractClaims(token);

        assertThat(claims).isNotNull();
        assertThat(claims.getSubject()).isEqualTo("testuser");
    }

    @Test
    void validateToken_withMalformedToken_shouldThrowException() {
        assertThatThrownBy(() -> jwtTokenService.validateAndExtractClaims("malformed.token"))
                .isInstanceOf(JwtAuthenticationException.class)
                .hasFieldOrPropertyWithValue("errorCode", JwtAuthenticationException.ErrorCode.TOKEN_MALFORMED);
    }

    @Test
    void validateToken_withInvalidSignature_shouldThrowException() {
        String tamperedToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.tampered";

        assertThatThrownBy(() -> jwtTokenService.validateAndExtractClaims(tamperedToken))
                .isInstanceOf(JwtAuthenticationException.class);
    }

    @Test
    void extractUsername_shouldReturnCorrectUsername() {
        JwtUserDetails userDetails = new JwtUserDetails(
                1L, "testuser", "",
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                true
        );

        String token = jwtTokenService.generateToken(userDetails);
        String username = jwtTokenService.extractUsername(token);

        assertThat(username).isEqualTo("testuser");
    }

    @Test
    void getExpirationSeconds_shouldReturnCorrectValue() {
        assertThat(jwtTokenService.getExpirationSeconds()).isEqualTo(86400L);
    }
}
