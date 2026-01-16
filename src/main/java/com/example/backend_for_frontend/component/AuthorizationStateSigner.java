package com.example.backend_for_frontend.component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class AuthorizationStateSigner {
	private static final String HMAC_ALGO = "HmacSHA256";
	private static final String SECRET = "supersecretkey";

	public static String sign(String payload) {
		try {
			Mac mac = Mac.getInstance(HMAC_ALGO);
			mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), HMAC_ALGO));
			byte[] signature = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));

			return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
		} catch (Exception e) {
			throw new IllegalStateException("Failed to sign AuthorizationState", e);
		}
	}
}
