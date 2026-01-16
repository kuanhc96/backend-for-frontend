package com.example.backend_for_frontend.controller;

import java.net.URI;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/oauth")
public class LoginController {
    @Value("${authserver.location}")
    private String authServerLocation;

    @Value("${client.location}")
    private String clientLocation;

    @GetMapping("/login")
    public void authorize(HttpServletResponse response) {
        URI uri = UriComponentsBuilder.fromUriString(authServerLocation + "/login").build().toUri();
        response.setHeader("Location", uri.toString());
        response.setHeader("Access-Control-Allow-Credentials", clientLocation);
        response.setStatus(HttpStatus.FOUND.value());
    }
}
