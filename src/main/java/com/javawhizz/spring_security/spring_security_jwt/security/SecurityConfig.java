package com.javawhizz.spring_security.spring_security_jwt.security;

import com.javawhizz.spring_security.spring_security_jwt.jwt.JwtAuthConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwtSetUri;

    private final JwtAuthConverter jwtAuthConverter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                        .authorizeHttpRequests((httpRequests) ->
                                httpRequests.anyRequest()
                                        .authenticated())
                .oauth2ResourceServer((oauth2ResourceServer) ->
                        oauth2ResourceServer.jwt((jwt) ->
                                jwt.decoder(jwtDecoder())
                                        .jwtAuthenticationConverter(jwtAuthConverter)));

        http.sessionManagement((sessionManagement) ->
                sessionManagement.sessionCreationPolicy(STATELESS));

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withJwkSetUri(jwtSetUri).build();
    }
}
