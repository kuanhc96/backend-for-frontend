package com.example.backend_for_frontend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
//import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
//import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.web.client.RestTemplate;

//import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
public class BffConfig {
    @Bean
    public RestTemplate authServerClient() {
        return new RestTemplate();
    }

//    @Bean
//    public HttpMessageConverters messageConverters(ObjectMapper objectMapper) {
//        return new HttpMessageConverters(new MappingJackson2HttpMessageConverter(objectMapper));
//    }
}
