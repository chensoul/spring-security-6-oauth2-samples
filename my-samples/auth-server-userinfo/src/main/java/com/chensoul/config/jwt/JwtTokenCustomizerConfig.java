package com.chensoul.config.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Set;

@Configuration
public class JwtTokenCustomizerConfig {

	// @formatter:off
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return (context) -> {
			if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
				Set<String> authorities = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities());
				context.getClaims().claim("authorities", authorities);
			}
		};
	}
	// @formatter:on

}