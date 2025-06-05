package com.chensoul.security;

import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

public class CustomCodeGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
	private final String code;

	public CustomCodeGrantAuthenticationToken(String code, Authentication clientPrincipal,
			@Nullable Map<String, Object> additionalParameters) {
		super(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:custom_code"),
				clientPrincipal, additionalParameters);
		Assert.hasText(code, "code cannot be empty");
		this.code = code;
	}

	public String getCode() {
		return this.code;
	}

}