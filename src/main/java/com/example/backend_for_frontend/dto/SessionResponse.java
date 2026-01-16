package com.example.backend_for_frontend.dto;

import lombok.Builder;

@Builder
public record SessionResponse(String userGUID, String email, String role) {
}
