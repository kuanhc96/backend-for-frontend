package com.example.backend_for_frontend.dto;

import lombok.Builder;

@Builder
public record AuthorizationState(boolean rememberMe, String successUrl) {}
