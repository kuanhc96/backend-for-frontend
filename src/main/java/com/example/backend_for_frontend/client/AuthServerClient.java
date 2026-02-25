package com.example.backend_for_frontend.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;

import com.example.backend_for_frontend.config.AuthServerClientConfig;


@FeignClient(name = "authserver-client", url = "${authserver.location}", configuration = AuthServerClientConfig.class)
public interface AuthServerClient {
	@PostMapping(value = "/api/verify/state", consumes = "application/json")
	Boolean verifyState(String state);

}
