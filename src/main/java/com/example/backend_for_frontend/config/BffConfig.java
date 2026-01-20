package com.example.backend_for_frontend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
//import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
//import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

//import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
public class BffConfig {
    @Value("${authserver.location}")
    private String authServerLocation;

    @Bean
    public RestTemplate authServerClient() {
        return new RestTemplate();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withIssuerLocation(authServerLocation).build();
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.disable())
                .csrf(csrf -> csrf.disable());
        return http.build();
    }

//    @Bean
//    public HttpMessageConverters messageConverters(ObjectMapper objectMapper) {
//        return new HttpMessageConverters(new MappingJackson2HttpMessageConverter(objectMapper));
//    }
}
