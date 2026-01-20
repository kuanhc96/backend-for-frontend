package com.example.backend_for_frontend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
public class BackendForFrontendApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendForFrontendApplication.class, args);
	}

}
