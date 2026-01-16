package com.example.backend_for_frontend.component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import com.fasterxml.jackson.databind.ObjectMapper;

public class AuthorizationStateDecoder {
	private static final ObjectMapper mapper = new ObjectMapper();

	public static boolean verifySignature(String encodedState) {
		String[] parts = encodedState.split("\\.");
		if (parts.length != 2) {
			return false;
		}

		String payload = parts[0];
		String receivedSignature = parts[1];

		String expectedSignature = AuthorizationStateSigner.sign(payload);
		if (!MessageDigest.isEqual(expectedSignature.getBytes(StandardCharsets.UTF_8),
				receivedSignature.getBytes(StandardCharsets.UTF_8))
		) {
			return false;
		}

		return true;
	}
}
