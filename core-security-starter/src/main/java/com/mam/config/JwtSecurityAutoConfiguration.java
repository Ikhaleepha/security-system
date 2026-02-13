package com.mam.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mam.filter.JwtAccessDeniedHandler;
import com.mam.filter.JwtAuthenticationEntryPoint;
import com.mam.filter.JwtAuthenticationFilter;
import com.mam.service.JwtTokenService;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.web.SecurityFilterChain;

@AutoConfiguration
@ConditionalOnClass({SecurityFilterChain.class, Jwts.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(JwtProperties.class)
@ComponentScan(basePackages = "com.mam")
public class JwtSecurityAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(JwtSecurityAutoConfiguration.class);

    @PostConstruct
    public void init() {
        log.info("JWT Security Auto-Configuration initialized");
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenService jwtTokenService(JwtProperties jwtProperties) {
        return new JwtTokenService(jwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtTokenService jwtTokenService) {
        return new JwtAuthenticationFilter(jwtTokenService);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint(ObjectMapper objectMapper) {
        return new JwtAuthenticationEntryPoint(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAccessDeniedHandler jwtAccessDeniedHandler(ObjectMapper objectMapper) {
        return new JwtAccessDeniedHandler(objectMapper);
    }
}
