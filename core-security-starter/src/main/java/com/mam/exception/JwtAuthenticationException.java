package com.mam.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtAuthenticationException extends AuthenticationException {

    public enum ErrorCode {
        TOKEN_EXPIRED,
        TOKEN_INVALID,
        TOKEN_MALFORMED,
        TOKEN_MISSING
    }

    private final ErrorCode errorCode;

    public JwtAuthenticationException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public JwtAuthenticationException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
