package com.example.backend_for_frontend.component;


import com.example.backend_for_frontend.dto.AuthorizationState;

public class AuthorizationStateCodec {
	public static String encode(AuthorizationState state) {
		String payload = AuthorizationStateEncoder.encode(state);
		String signature = AuthorizationStateSigner.sign(payload);
		return payload + "." + signature;
	}
}
