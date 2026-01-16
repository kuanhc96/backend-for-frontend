package com.example.backend_for_frontend.dto;

public record TokenResponse(
        String access_token,
        String refresh_token,
        String scope,
        String id_token,
        String token_type,
        Integer expires_in
) {
}
