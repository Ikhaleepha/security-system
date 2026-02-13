package com.mam.model;

import java.util.List;

public record AuthResponse(
        String token,
        String tokenType,
        long expiresIn,
        String username,
        List<String> roles
) {
    public static AuthResponse of(String token, long expiresInSeconds, String username, List<String> roles) {
        return new AuthResponse(token, "Bearer", expiresInSeconds, username, roles);
    }
}
