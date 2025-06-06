package com.chensoul.config.idtoken;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class IdTokenCustomizerConfig {

	@Bean
	public OidcUserInfoService userInfoService() {
		return new OidcUserInfoService();
	}

	// @formatter:off
	@Bean // <1>
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
			OidcUserInfoService userInfoService) {
		return (context) -> {
			if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
				OidcUserInfo userInfo = userInfoService.loadUser( // <2>
						context.getPrincipal().getName());
				context.getClaims().claims(claims ->
						claims.putAll(userInfo.getClaims()));
			}
		};
	}
	// @formatter:on

}