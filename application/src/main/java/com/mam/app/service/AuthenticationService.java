package com.mam.app.service;

import com.mam.model.AuthRequest;
import com.mam.model.AuthResponse;
import com.mam.model.JwtUserDetails;
import com.mam.service.JwtTokenService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;
    private final UserDetailsService userDetailsService;

    public AuthenticationService(AuthenticationManager authenticationManager,
                                 JwtTokenService jwtTokenService,
                                 UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenService = jwtTokenService;
        this.userDetailsService = userDetailsService;
    }

    public AuthResponse authenticate(AuthRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        JwtUserDetails userDetails = (JwtUserDetails)
                userDetailsService.loadUserByUsername(request.username());

        String token = jwtTokenService.generateToken(userDetails);

        return AuthResponse.of(
                token,
                jwtTokenService.getExpirationSeconds(),
                userDetails.getUsername(),
                userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
        );
    }
}
