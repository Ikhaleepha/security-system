package com.mam.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mam.filter.CachedBodyHttpServletRequest;
import com.mam.model.AuthRequest;
import com.mam.model.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(SecurityExceptionHandler.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @ExceptionHandler(JwtAuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleJwtAuthenticationException(
            JwtAuthenticationException ex, HttpServletRequest request) {

        log.warn("JWT authentication failed: {} - {} | User: {} | URL: {} {}",
                ex.getErrorCode(), ex.getMessage(), extractUsername(request), request.getMethod(), request.getRequestURI());

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ErrorResponse.of(401, "Unauthorized", ex.getMessage(), request.getRequestURI()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(
            AccessDeniedException ex, HttpServletRequest request) {

        log.warn("Access denied: {} | User: {} | URL: {} {}",
                ex.getMessage(), extractUsername(request), request.getMethod(), request.getRequestURI());

        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ErrorResponse.of(403, "Forbidden", "Access denied", request.getRequestURI()));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(
            AuthenticationException ex, HttpServletRequest request) {

        log.warn("Authentication failed: {} | User: {} | URL: {} {}",
                ex.getMessage(), extractUsername(request), request.getMethod(), request.getRequestURI());

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ErrorResponse.of(401, "Unauthorized", "Authentication failed", request.getRequestURI()));
    }

    private String extractUsername(HttpServletRequest request) {
        try {
            CachedBodyHttpServletRequest cachedRequest = unwrapRequest(request);
            if (cachedRequest != null) {
                byte[] content = cachedRequest.getCachedBody();
                if (content.length > 0) {
                    AuthRequest authRequest = objectMapper.readValue(content, AuthRequest.class);
                    return authRequest.username();
                }
            }
        } catch (Exception e) {
            log.debug("Could not extract username from request body: {}", e.getMessage());
        }
        return "unknown";
    }

    private CachedBodyHttpServletRequest unwrapRequest(HttpServletRequest request) {
        HttpServletRequest current = request;
        while (current != null) {
            if (current instanceof CachedBodyHttpServletRequest cached) {
                return cached;
            }
            if (current instanceof HttpServletRequestWrapper wrapper) {
                current = (HttpServletRequest) wrapper.getRequest();
            } else {
                break;
            }
        }
        return null;
    }
}
