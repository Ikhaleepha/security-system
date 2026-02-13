package com.mam.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "mam.security.jwt")
public class JwtProperties {

    /**
     * Base64-encoded secret key for signing JWTs (minimum 256 bits for HS256)
     */
    private String secret;

    /**
     * Token expiration time in milliseconds (default: 86400000 = 24 hours)
     */
    private long expirationMs = 86400000L;

    /**
     * Token issuer claim
     */
    private String issuer = "mam-security";

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    public void setExpirationMs(long expirationMs) {
        this.expirationMs = expirationMs;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
}
