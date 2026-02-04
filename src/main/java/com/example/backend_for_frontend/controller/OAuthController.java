package com.example.backend_for_frontend.controller;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.example.backend_for_frontend.client.AuthServerClient;
import com.example.backend_for_frontend.dto.AuthorizationState;
import com.example.backend_for_frontend.dto.SessionResponse;
import com.example.backend_for_frontend.dto.TokenResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import redis.clients.jedis.RedisClient;
import redis.clients.jedis.params.SetParams;

@RestController
@RequestMapping("/api/oauth")
@RequiredArgsConstructor
public class OAuthController {
	@Value("${client.location}")
	private String clientLocation;

	@Value("${authserver.location:http://localhost:9000}")
	private String authServerLocation;

	@Value("${rememberme.expiration-hours:8}")
	private Integer rememberMeExpirationHours;

	private static final ObjectMapper mapper = new ObjectMapper();

	private final JwtDecoder jwtDecoder;
	private final RedisClient redisClient;
	private final RestTemplate authServerRedirectClient;
	private final AuthServerClient authServerClient;

    @GetMapping("/status")
    public ResponseEntity<SessionResponse> getOpenIdSession(HttpServletRequest request, HttpServletResponse response) {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Access-Control-Allow-Origin", clientLocation);
        responseHeaders.add("Access-Control-Allow-Credentials", "true");

		// check if the user has a valid access token associated with the session
		// get the current session's JSESSIONID cookie
		if (ObjectUtils.isEmpty(request.getCookies())) {
			SessionResponse emptySession = SessionResponse.builder().email("").role("").userGUID("").build();
			return ResponseEntity.ok().headers(responseHeaders).body(emptySession);
		}
		Cookie rememberMeCookie = Arrays.stream(request.getCookies()).filter(c -> "RMC".equals(c.getName())).findFirst().orElse(null);
		String jSessionId = request.getRequestedSessionId() == null? request.getSession(true).getId() : request.getRequestedSessionId();
		String accessToken = null;
		String idToken = null;
		if (rememberMeCookie != null) {
			// access token expired
			// user previously selected the "remember me" option

			// get rememberMeCookie
			String rememberMeCookieId = rememberMeCookie.getValue();

			// get the refreshToken associated with the rememberMeCookie from redis
			String refreshToken = redisClient.get(generateRefreshTokenKey(rememberMeCookieId));

			// use the refresh token to get a new access token
			TokenResponse tokenResponse = sendTokenRequest(refreshToken);
			if (tokenResponse == null) {
				// rememberMe token is invalid/expired
				SessionResponse emptySession = SessionResponse.builder().email("").role("").userGUID("").build();
				return ResponseEntity.ok().headers(responseHeaders).body(emptySession);
			} else {
				accessToken = tokenResponse.access_token();
				idToken = tokenResponse.id_token();
				String newRefreshToken = tokenResponse.refresh_token();
				redisClient.set(generateAccessTokenKey(jSessionId), accessToken, SetParams.setParams().nx().ex(rememberMeExpirationHours * 3600L));
				redisClient.set(generateOpenIdTokenKey(jSessionId), idToken, SetParams.setParams().nx().ex(rememberMeExpirationHours * 3600L));
				Long rememberMeExpirationSeconds = rememberMeExpirationHours * 3600L;
				String newRememberMeCookieId = UUID.randomUUID().toString();
				redisClient.set(generateRefreshTokenKey(newRememberMeCookieId), newRefreshToken, SetParams.setParams().nx().ex(rememberMeExpirationSeconds));

				Cookie newRememberMeCookie = new Cookie("RMC", newRememberMeCookieId);
				newRememberMeCookie.setMaxAge((int) Duration.ofHours(rememberMeExpirationHours).toSeconds());
				newRememberMeCookie.setDomain(null);
				newRememberMeCookie.setPath("/");
				newRememberMeCookie.setHttpOnly(true);
				newRememberMeCookie.setSecure(true);
//				newRememberMeCookie.setAttribute("SameSite", "Strict");
//				newRememberMeCookie.setAttribute("Partitioned", "false");
				response.addCookie(newRememberMeCookie);

			}
		} else {
			// get the accessToken and idToken associated with the JSESSIONID from redis
			accessToken = redisClient.get(generateAccessTokenKey(jSessionId));
			if (StringUtils.isBlank(accessToken)) {
				SessionResponse emptySession = SessionResponse.builder().email("").role("").userGUID("").build();
				return ResponseEntity.ok().headers(responseHeaders).body(emptySession);
			}
			idToken = redisClient.get(generateOpenIdTokenKey(jSessionId));
		}

		Jwt jwt = jwtDecoder.decode(idToken);

		Map<String, String> claims = jwt.getClaims().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> String.valueOf(entry.getValue())));
		SessionResponse sessionResponse = SessionResponse.builder()
				.userGUID(claims.get("userGUID"))
				.email(claims.get("sub"))
				.role(claims.get("role"))
				.build();
		return ResponseEntity.ok().headers(responseHeaders).body(sessionResponse);
    }

	@PostMapping("/tokens")
	public ResponseEntity<?> callback(
			HttpServletRequest request,
			HttpServletResponse response,
            @RequestParam(required = false) String code,
			@RequestParam(required = false) String state,
            @RequestParam(required = false) String error) throws IOException {

		verifyState(state);
		AuthorizationState authState = parseState(state);

		TokenResponse tokenResponse = sendTokenRequest(code, state);

		if (tokenResponse != null) {
            String accessToken = tokenResponse.access_token();
            String refreshToken = tokenResponse.refresh_token();
            String idToken = tokenResponse.id_token();
			Integer expiresIn = tokenResponse.expires_in();

			String jSessionId = Arrays.stream(request.getCookies()).filter(c -> "JSESSIONID".equals(c.getName())).findFirst().orElse(null).getValue();

			redisClient.set(generateAccessTokenKey(jSessionId), accessToken, SetParams.setParams().nx().ex(expiresIn));

			if (authState.rememberMe()) {
				Long rememberMeExpirationSeconds = rememberMeExpirationHours * 3600L;
				String rememberMeCookieId = UUID.randomUUID().toString();
				redisClient.set(generateRefreshTokenKey(rememberMeCookieId), refreshToken, SetParams.setParams().nx().ex(rememberMeExpirationSeconds));

				Cookie newRememberMeCookie = new Cookie("RMC", rememberMeCookieId);
				newRememberMeCookie.setMaxAge((int) Duration.ofHours(rememberMeExpirationHours).toSeconds());
				newRememberMeCookie.setDomain(null);
				newRememberMeCookie.setPath("/");
				newRememberMeCookie.setHttpOnly(true);
				newRememberMeCookie.setSecure(true);
//				newRememberMeCookie.setAttribute("SameSite", "Strict");
//				newRememberMeCookie.setAttribute("Partitioned", "false");
				response.addCookie(newRememberMeCookie);

			}
			redisClient.set(generateOpenIdTokenKey(jSessionId), idToken, SetParams.setParams().nx().ex(expiresIn));

			HttpHeaders responseHeaders = new HttpHeaders();
			responseHeaders.add("Access-Control-Allow-Origin", clientLocation);
			responseHeaders.add("Access-Control-Allow-Credentials", "true");
			return ResponseEntity.ok().headers(responseHeaders).body(Map.of("successUrl", authState.successUrl()));
		} else {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed to retrieve access token");
		}
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
		HttpHeaders responseHeaders = new HttpHeaders();
		responseHeaders.add("Access-Control-Allow-Origin", clientLocation);
		responseHeaders.add("Access-Control-Allow-Credentials", "true");

		// check if the user has a valid access token associated with the session
		// get the current session's JSESSIONID cookie
		if (ObjectUtils.isEmpty(request.getCookies())) {
			return ResponseEntity.ok().headers(responseHeaders).build();
		}
		Cookie rememberMeCookie = Arrays.stream(request.getCookies()).filter(c -> "RMC".equals(c.getName())).findFirst().orElse(null);
		String jSessionId = request.getSession(true).getId();
		if (rememberMeCookie != null) {
			// get rememberMeCookie
			String rememberMeCookieId = rememberMeCookie.getValue();

			// delete refresh token from redis
			redisClient.del(generateRefreshTokenKey(rememberMeCookieId));

			Cookie deleteRememberMeCookie = new Cookie("RMC", null);
			deleteRememberMeCookie.setMaxAge(0);
			deleteRememberMeCookie.setDomain(null);
			deleteRememberMeCookie.setPath("/");
			deleteRememberMeCookie.setSecure(true);
			deleteRememberMeCookie.setHttpOnly(true);
			response.addCookie(deleteRememberMeCookie);
		}
		redisClient.del(generateAccessTokenKey(jSessionId));
		redisClient.del(generateOpenIdTokenKey(jSessionId));
		request.changeSessionId();
		return ResponseEntity.ok().headers(responseHeaders).build();
	}

	private String generateAccessTokenKey(String id) {
		return "access_token#" + id;
	}

	private String generateRefreshTokenKey(String id) {
		return "refresh_token#" + id;
	}

	private String generateOpenIdTokenKey(String id) {
		return "openid_token#" + id;
	}

	private void verifyState(String state) {
		Boolean isValidStateResponse = authServerClient.verifyState(state);

		if (isValidStateResponse == null || !isValidStateResponse) {
			throw new IllegalArgumentException("Invalid state parameter");
		}
	}

	private AuthorizationState parseState(String state) throws IOException {
		String[] parts = state.split("\\.");
		String payload = parts[0];
		byte[] jsonBytes = Base64.getUrlDecoder().decode(payload);
		return mapper.readValue(jsonBytes, AuthorizationState.class);
	}

	private TokenResponse sendTokenRequest(String code, String state) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("grant_type", "authorization_code");
		body.add("code", code);
		body.add("state", state);
		body.add("redirect_uri", clientLocation + "/callback"); // is this needed in the token API request?
		body.add("client_id", "fe-client");
		body.add("client_secret", "secret1");
		HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(body, headers);
		return authServerRedirectClient.exchange(
				authServerLocation + "/oauth2/token",
				HttpMethod.POST,
				tokenRequest,
				TokenResponse.class
		).getBody();
	}

	private TokenResponse sendTokenRequest(String refreshToken) {
		if (StringUtils.isBlank(refreshToken)) {
			return null;
		}
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("grant_type", "refresh_token");
		body.add("redirect_uri", clientLocation + "/callback"); // is this needed in the token API request?
		body.add("client_id", "fe-client");
		body.add("client_secret", "secret1");
		body.add("refresh_token", refreshToken);
		HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(body, headers);
		return authServerRedirectClient.exchange(
				authServerLocation + "/oauth2/token",
				HttpMethod.POST,
				tokenRequest,
				TokenResponse.class
		).getBody();
	}
}
