package com.mam.service;

import com.mam.config.JwtProperties;
import com.mam.exception.JwtAuthenticationException;
import com.mam.exception.JwtAuthenticationException.ErrorCode;
import com.mam.model.JwtUserDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;

import java.security.Key;
import java.util.*;

public class JwtTokenService {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenService.class);

    private final JwtProperties jwtProperties;
    private final Key signingKey;

    public JwtTokenService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.getSecret()));
    }

    public String generateToken(JwtUserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userDetails.getUserId());
        claims.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList());

        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtProperties.getExpirationMs());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuer(jwtProperties.getIssuer())
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims validateAndExtractClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.debug("Token expired: {}", e.getMessage());
            throw new JwtAuthenticationException(ErrorCode.TOKEN_EXPIRED, "Token has expired", e);
        } catch (MalformedJwtException e) {
            log.debug("Malformed token: {}", e.getMessage());
            throw new JwtAuthenticationException(ErrorCode.TOKEN_MALFORMED, "Malformed token", e);
        } catch (JwtException e) {
            log.debug("Invalid token: {}", e.getMessage());
            throw new JwtAuthenticationException(ErrorCode.TOKEN_INVALID, "Invalid token", e);
        }
    }

    public String extractUsername(String token) {
        return validateAndExtractClaims(token).getSubject();
    }

    public Long extractUserId(Claims claims) {
        Object userId = claims.get("userId");
        if (userId instanceof Integer) {
            return ((Integer) userId).longValue();
        }
        return (Long) userId;
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(Claims claims) {
        Object roles = claims.get("roles");
        if (roles instanceof List<?>) {
            return (List<String>) roles;
        }
        return Collections.emptyList();
    }

    public boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public long getExpirationSeconds() {
        return jwtProperties.getExpirationMs() / 1000;
    }
}
